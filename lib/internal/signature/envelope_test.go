package signature

import (
	"bytes"
	"strings"
	"testing"
)

// TestParseAcceptsRFC5321EnvelopePaths verifies null, mailbox, quoted, routed, and literal paths.
func TestParseAcceptsRFC5321EnvelopePaths(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		path string
	}{
		{name: "null reverse path", tag: "mf", path: "<>"},
		{name: "dot string mailbox", tag: "mf", path: "<sender.name+tag@example.test>"},
		{name: "quoted local part", tag: "mf", path: `<"quoted local"@example.test>`},
		{name: "quoted pair", tag: "rt", path: `<"quoted\\\"local"@example.test>`},
		{name: "source route", tag: "rt", path: "<@route.example,@next.example:user@example.test>"},
		{name: "ipv4 address literal", tag: "rt", path: "<user@[192.0.2.1]>"},
		{name: "ipv6 address literal", tag: "rt", path: "<user@[IPv6:2001:db8::1]>"},
		{name: "general address literal", tag: "rt", path: "<user@[X400:printable-value]>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := Parse(dkim2SignatureField(t, 0, signatureValueWith(tt.tag, baseValue(tt.path))))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if tt.tag == "mf" && string(parsed.MailFrom().Value()) != tt.path {
				t.Fatalf("MailFrom() = %q, want preserved %q", parsed.MailFrom().Value(), tt.path)
			}
		})
	}
}

// TestCanonicalEnvelopePathNormalizesOnlyGrammarOwnedDomainPositions verifies shared path identity.
func TestCanonicalEnvelopePathNormalizesOnlyGrammarOwnedDomainPositions(t *testing.T) {
	input := []byte(`<@ROUTE.Example,@NEXT.Example:"LoC@al"@[X400:A@B]>`)
	want := []byte(`<@route.example,@next.example:"LoC@al"@[x400:a@b]>`)
	got, ok := CanonicalEnvelopePath(input, false)
	if !ok || !bytes.Equal(got, want) {
		t.Fatalf("CanonicalEnvelopePath() = %q, %t, want %q", got, ok, want)
	}
	input[2] = 'x'
	if !bytes.Equal(got, want) {
		t.Fatal("caller mutation changed canonical path")
	}

	for _, invalid := range [][]byte{
		nil,
		[]byte("user@example.test"),
		[]byte("<>"),
		[]byte("<@route.example,user@example.test>"),
	} {
		if canonical, valid := CanonicalEnvelopePath(invalid, false); valid || canonical != nil {
			t.Fatalf("CanonicalEnvelopePath(%q) = %q, %t, want invalid", invalid, canonical, valid)
		}
	}
	if canonical, valid := CanonicalEnvelopePath([]byte("<>"), true); !valid || !bytes.Equal(canonical, []byte("<>")) {
		t.Fatalf("CanonicalEnvelopePath(null) = %q, %t", canonical, valid)
	}
}

// TestParseRejectsNonRFC5321EnvelopePaths verifies mailbox grammar and ASCII-only draft imports.
func TestParseRejectsNonRFC5321EnvelopePaths(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		path string
	}{
		{name: "null forward path", tag: "rt", path: "<>"},
		{name: "missing mailbox", tag: "mf", path: "<not a mailbox>"},
		{name: "space outside quotes", tag: "mf", path: "<sender @example.test>"},
		{name: "leading dot", tag: "mf", path: "<.sender@example.test>"},
		{name: "trailing dot", tag: "mf", path: "<sender.@example.test>"},
		{name: "empty domain label", tag: "mf", path: "<sender@example..test>"},
		{name: "hyphen domain edge", tag: "mf", path: "<sender@-example.test>"},
		{name: "unterminated quoted local", tag: "mf", path: `<"sender@example.test>`},
		{name: "quoted control", tag: "mf", path: "<\"bad\x1flocal\"@example.test>"},
		{name: "bad source route", tag: "rt", path: "<@route.example,user@example.test>"},
		{name: "invalid ipv4 literal", tag: "rt", path: "<user@[999.0.2.1]>"},
		{name: "invalid ipv6 literal", tag: "rt", path: "<user@[IPv6:not-an-address]>"},
		{name: "invalid general literal", tag: "rt", path: "<user@[X400:bad\\value]>"},
		{name: "utf8 local part", tag: "mf", path: "<séndér@example.test>"},
		{name: "utf8 domain", tag: "mf", path: "<sender@éxample.test>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith(tt.tag, baseValue(tt.path))))
			if !IsErrorCode(err, ErrorCodeInvalidEnvelopePath) {
				t.Fatalf("Parse() error = %v, want invalid envelope path", err)
			}
		})
	}
}

// TestParseEnforcesRFC5321EnvelopeBoundaries verifies path, local-part, and label limits.
func TestParseEnforcesRFC5321EnvelopeBoundaries(t *testing.T) {
	local64 := strings.Repeat("a", 64)
	domain189 := domainWithLabelLengths(63, 63, 61)
	domain190 := domainWithLabelLengths(63, 63, 62)
	tests := []struct {
		name string
		path string
		ok   bool
	}{
		{name: "256 byte path", path: "<" + local64 + "@" + domain189 + ">", ok: true},
		{name: "257 byte path", path: "<" + local64 + "@" + domain190 + ">", ok: false},
		{name: "64 byte local part", path: "<" + local64 + "@example.test>", ok: true},
		{name: "65 byte local part", path: "<" + strings.Repeat("a", 65) + "@example.test>", ok: false},
		{name: "63 byte label", path: "<user@" + strings.Repeat("a", 63) + ".test>", ok: true},
		{name: "64 byte label", path: "<user@" + strings.Repeat("a", 64) + ".test>", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("rt", baseValue(tt.path))))
			if tt.ok && err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if !tt.ok && !IsErrorCode(err, ErrorCodeInvalidEnvelopePath) {
				t.Fatalf("Parse() error = %v, want invalid envelope path", err)
			}
		})
	}
}

// TestSMTPDomainEnforcesTotalLength verifies the RFC 5321 domain-size boundary directly.
func TestSMTPDomainEnforcesTotalLength(t *testing.T) {
	domain255 := domainWithLabelLengths(63, 63, 63, 63)
	domain256 := domainWithLabelLengths(50, 50, 50, 50, 52)
	if len(domain255) != 255 || !validSMTPDomain([]byte(domain255)) {
		t.Fatalf("255-byte domain rejected: length=%d", len(domain255))
	}
	if len(domain256) != 256 || validSMTPDomain([]byte(domain256)) {
		t.Fatalf("256-byte domain accepted: length=%d", len(domain256))
	}
}

// TestParseEnforcesRFC5321QuotedPairEdges verifies quoted-pairSMTP byte boundaries.
func TestParseEnforcesRFC5321QuotedPairEdges(t *testing.T) {
	for _, path := range []string{
		"<\"a\\ b\"@example.test>",
		"<\"a\\~b\"@example.test>",
	} {
		if _, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("rt", baseValue(path)))); err != nil {
			t.Fatalf("Parse(%q) error = %v", path, err)
		}
	}
	for _, path := range []string{
		"<\"a\\\x1fb\"@example.test>",
		"<\"a\\\x7fb\"@example.test>",
	} {
		_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("rt", baseValue(path))))
		if !IsErrorCode(err, ErrorCodeInvalidEnvelopePath) {
			t.Fatalf("Parse(%q) error = %v, want invalid envelope path", path, err)
		}
	}
}

// domainWithLabelLengths constructs a valid ASCII domain with requested label sizes.
func domainWithLabelLengths(lengths ...int) string {
	labels := make([]string, len(lengths))
	for index, length := range lengths {
		labels[index] = strings.Repeat("a", length)
	}

	return strings.Join(labels, ".")
}

// TestParseRejectsMalformedEnvelopePaths verifies parser-level path shape.
func TestParseRejectsMalformedEnvelopePaths(t *testing.T) {
	tests := []struct {
		name string
		in   string
		code ErrorCode
	}{
		{name: "mf invalid base64", in: "not_base64", code: ErrorCodeInvalidEnvelopeBase64},
		{name: "mf not bracketed", in: baseValue("not-bracketed"), code: ErrorCodeInvalidEnvelopePath},
		{name: "mf has cr", in: baseValue("<bad\r@example.test>"), code: ErrorCodeInvalidEnvelopePath},
		{name: "mf has lf", in: baseValue("<bad\n@example.test>"), code: ErrorCodeInvalidEnvelopePath},
		{name: "mf has nul", in: baseValue("<bad\x00@example.test>"), code: ErrorCodeInvalidEnvelopePath},
		{name: "rt empty list", in: "", code: ErrorCodeInvalidEnvelopePath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := signatureValueWith("mf", tt.in)
			if tt.name == "rt empty list" {
				value = signatureValueWith("rt", tt.in)
			}
			_, err := Parse(dkim2SignatureField(t, 0, value))
			if !IsErrorCode(err, tt.code) {
				t.Fatalf("Parse() error = %v, want %s", err, tt.code)
			}
		})
	}
}

// TestParserRejectsRecipientLimit verifies rt= count limits.
func TestParserRejectsRecipientLimit(t *testing.T) {
	parser, err := NewParser(Limits{MaxRecipients: 1})
	if err != nil {
		t.Fatalf("NewParser() error = %v", err)
	}

	value := signatureValueWith("rt", baseValue("<one@example.test>")+","+baseValue("<two@example.test>"))
	_, err = parser.ParseField(dkim2SignatureField(t, 0, value))
	if !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("ParseField() error = %v, want limit exceeded", err)
	}
}

// TestEnvelopePathAccessorsReturnImmutableCopies verifies decoded path copying.
func TestEnvelopePathAccessorsReturnImmutableCopies(t *testing.T) {
	parsed, err := Parse(dkim2SignatureField(t, 0, validSignatureValue()))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	mailFrom := parsed.MailFrom()
	path := mailFrom.Value()
	path[1] = 'X'
	if got := mailFrom.Value(); bytes.Equal(got, path) {
		t.Fatalf("MailFrom().Value() reused mutable storage")
	}

	recipients := parsed.Recipients()
	recipients[0] = EnvelopePath{}
	if got := parsed.Recipients(); len(got) != 1 || string(got[0].Value()) != "<user@example.net>" {
		t.Fatalf("Recipients() after mutation = %#v", got)
	}
}
