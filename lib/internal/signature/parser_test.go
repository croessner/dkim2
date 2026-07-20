package signature

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/tagvalue"
)

const (
	testSelector     = "selector1"
	testSequenceTag  = "i=2"
	testInstanceTag  = "m=3"
	testTimestampTag = "t=1000000000000"
	testDomainTag    = "d=Example.ORG"
)

// TestParseAcceptsDKIM2Signature verifies required and optional tags.
func TestParseAcceptsDKIM2Signature(t *testing.T) {
	field := dkim2SignatureField(t, 11, validSignatureValue()+"; n=printable nonce; f=feedback, unknown_flag; x_ext=ignored")

	parsed, err := Parse(field)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.Sequence() != 2 {
		t.Fatalf("Sequence() = %d, want 2", parsed.Sequence())
	}
	if parsed.InstanceNumber() != 3 {
		t.Fatalf("InstanceNumber() = %d, want 3", parsed.InstanceNumber())
	}
	if parsed.TimestampSeconds() != 1000000000000 {
		t.Fatalf("TimestampSeconds() = %d, want 1000000000000", parsed.TimestampSeconds())
	}
	if parsed.HeaderIndex() != 11 {
		t.Fatalf("HeaderIndex() = %d, want 11", parsed.HeaderIndex())
	}
	if got := string(parsed.MailFrom().Value()); got != "<sender@example.test>" {
		t.Fatalf("MailFrom().Value() = %q", got)
	}
	if got := parsed.Domain(); got != "example.org" {
		t.Fatalf("Domain() = %q, want example.org", got)
	}
	if nonce, ok := parsed.Nonce(); !ok || string(nonce) != "printable nonce" {
		t.Fatalf("Nonce() = %q, %v", nonce, ok)
	}

	recipients := parsed.Recipients()
	if len(recipients) != 1 || string(recipients[0].Value()) != "<user@example.net>" {
		t.Fatalf("Recipients() = %#v", recipients)
	}

	sets := parsed.SignatureSets()
	if len(sets) != 1 {
		t.Fatalf("SignatureSets() length = %d, want 1", len(sets))
	}
	if sets[0].Selector() != testSelector || Algorithm(sets[0].Algorithm()) != AlgorithmEd25519SHA256 || !sets[0].KnownAlgorithm() {
		t.Fatalf("signature set metadata = %#v", sets[0])
	}
	if sets[0].Signature().DecodedLen() != 64 {
		t.Fatalf("signature decoded length = %d, want 64", sets[0].Signature().DecodedLen())
	}
}

// TestParseRejectsMissingFinalSemicolon reproduces the draft-04 DKIM2-Signature terminator rule.
func TestParseRejectsMissingFinalSemicolon(t *testing.T) {
	if _, err := Parse(headerField(t, 0, "DKIM2-Signature", validSignatureValue())); err == nil {
		t.Fatal("Parse() succeeded without the required final semicolon")
	}
}

// TestParseAcceptsNextDomainEnvelopeForm reproduces the draft-04 nd= envelope form.
func TestParseAcceptsNextDomainEnvelopeForm(t *testing.T) {
	parsed, err := Parse(dkim2SignatureField(t, 0, nextDomainSignatureValue()))
	if err != nil {
		t.Fatalf("Parse() error = %v, want valid nd= envelope form", err)
	}
	nextDomain, ok := parsed.NextDomain()
	if !ok || nextDomain != "next.example" || !parsed.HasNextDomain() {
		t.Fatalf("NextDomain() = %q, %v; HasNextDomain() = %v", nextDomain, ok, parsed.HasNextDomain())
	}
	if len(parsed.MailFrom().Value()) != 0 || len(parsed.Recipients()) != 0 {
		t.Fatal("nd= signature exposed mf=/rt= envelope data")
	}
}

// TestParseRejectsConflictingEnvelopeForms reproduces fail-closed nd=/mf=/rt= exclusivity.
func TestParseRejectsConflictingEnvelopeForms(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "nd with mf and rt", value: signatureValueWith("nd", "next.example")},
		{name: "nd with mf", value: nextDomainSignatureValue() + "; mf=" + baseValue("<sender@example.test>")},
		{name: "nd with rt", value: nextDomainSignatureValue() + "; rt=" + baseValue("<user@example.net>")},
		{name: "mf without rt", value: signatureValueWithout("rt")},
		{name: "rt without mf", value: signatureValueWithout("mf")},
		{name: "neither envelope form", value: strings.Join([]string{
			testSequenceTag,
			testInstanceTag,
			testTimestampTag,
			testDomainTag,
			"s=" + testSelector + ":ed25519-sha256:" + base64OfByte(0xaa, 64),
		}, "; ")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(dkim2SignatureField(t, 0, tt.value))
			if !IsErrorCode(err, ErrorCodeInvalidEnvelopeForm) {
				t.Fatalf("Parse() error = %v, want invalid envelope form", err)
			}
		})
	}
}

// TestParseRejectsWrongHeaderKind verifies parser-boundary header matching.
func TestParseRejectsWrongHeaderKind(t *testing.T) {
	field := headerField(t, 0, "Message-Instance", "m=1; h=value")
	_, err := Parse(field)
	if !IsErrorCode(err, ErrorCodeWrongHeaderField) {
		t.Fatalf("Parse() error = %v, want wrong header field", err)
	}
}

// TestParseRejectsMissingRequiredTags verifies fail-closed required tags.
func TestParseRejectsMissingRequiredTags(t *testing.T) {
	for _, tag := range []string{"i", "m", "t", "d", "s"} {
		t.Run("missing "+tag, func(t *testing.T) {
			_, err := Parse(dkim2SignatureField(t, 0, signatureValueWithout(tag)))
			if !IsErrorCode(err, ErrorCodeMissingRequiredTag) {
				t.Fatalf("Parse() error = %v, want missing required tag", err)
			}

			var signatureErr *Error
			if !errors.As(err, &signatureErr) {
				t.Fatal("errors.As did not expose signature Error")
			}
			if signatureErr.TagName() != tag {
				t.Fatalf("TagName() = %q, want %q", signatureErr.TagName(), tag)
			}
		})
	}
}

// TestParseRejectsInvalidSequenceAndInstanceNumbers verifies strict decimal syntax.
func TestParseRejectsInvalidSequenceAndInstanceNumbers(t *testing.T) {
	tests := []struct {
		tag   string
		value string
	}{
		{tag: "i", value: ""},
		{tag: "i", value: "0"},
		{tag: "i", value: "-1"},
		{tag: "i", value: "+1"},
		{tag: "i", value: "0x10"},
		{tag: "i", value: "18446744073709551616"},
		{tag: "m", value: "0"},
		{tag: "m", value: "1x"},
	}

	for _, tt := range tests {
		t.Run(tt.tag+"="+tt.value, func(t *testing.T) {
			_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith(tt.tag, tt.value)))
			if !IsErrorCode(err, ErrorCodeInvalidNumber) {
				t.Fatalf("Parse() error = %v, want invalid number", err)
			}
		})
	}
}

// TestParseRejectsInvalidTimestamps verifies t= unsigned decimal syntax.
func TestParseRejectsInvalidTimestamps(t *testing.T) {
	tests := []string{"", "-1", "+1", "1x", "18446744073709551616"}
	for _, value := range tests {
		t.Run("t="+value, func(t *testing.T) {
			_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("t", value)))
			if !IsErrorCode(err, ErrorCodeInvalidTimestamp) {
				t.Fatalf("Parse() error = %v, want invalid timestamp", err)
			}
		})
	}
}

// TestParseRejectsSharedTagSyntaxErrors verifies tagvalue remains authoritative.
func TestParseRejectsSharedTagSyntaxErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		code tagvalue.ErrorCode
	}{
		{name: "duplicate tag", in: validSignatureValue() + "; I=4", code: tagvalue.ErrorCodeDuplicateTag},
		{name: "empty interior tag", in: strings.Replace(validSignatureValue(), "; m=", ";; m=", 1), code: tagvalue.ErrorCodeEmptyTagSpec},
		{name: "invalid extension tag", in: validSignatureValue() + "; x-bad=1", code: tagvalue.ErrorCodeInvalidTagName},
		{name: "nonce semicolon", in: signatureValueWith("n", "bad;nonce"), code: tagvalue.ErrorCodeMissingEquals},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(dkim2SignatureField(t, 0, tt.in))
			if !tagvalue.IsErrorCode(err, tt.code) {
				t.Fatalf("Parse() error = %v, want tagvalue code %s", err, tt.code)
			}
		})
	}
}

// TestParseRejectsInvalidDomains verifies parser-level DNS name checks.
func TestParseRejectsInvalidDomains(t *testing.T) {
	tests := []string{"", ".example.org", "example.org.", "bad..example", "-bad.example", "bad-.example", "bad example", strings.Repeat("a", 64) + ".example"}
	for _, tag := range []string{"d", "nd"} {
		for _, value := range tests {
			t.Run(tag+"="+value, func(t *testing.T) {
				input := signatureValueWith("d", value)
				if tag == "nd" {
					input = strings.Replace(nextDomainSignatureValue(), "nd=Next.EXAMPLE", "nd="+value, 1)
				}
				_, err := Parse(dkim2SignatureField(t, 0, input))
				if !IsErrorCode(err, ErrorCodeInvalidDomain) {
					t.Fatalf("Parse() error = %v, want invalid domain", err)
				}
			})
		}
	}
}

// TestParseRejectsMalformedSignatureSets verifies s= tuple syntax.
func TestParseRejectsMalformedSignatureSets(t *testing.T) {
	tests := []string{
		"",
		signatureTestSelector,
		signatureTestSelector + ":ed25519-sha256",
		signatureTestSelector + ":ed25519-sha256:" + base64OfByte(0xaa, 64) + ":extra",
		":ed25519-sha256:" + base64OfByte(0xaa, 64),
		signatureTestSelector + "::" + base64OfByte(0xaa, 64),
	}

	for _, value := range tests {
		t.Run("s", func(t *testing.T) {
			_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("s", value)))
			if !IsErrorCode(err, ErrorCodeMalformedSignatureSet) {
				t.Fatalf("Parse() error = %v, want malformed signature set", err)
			}
		})
	}
}

// TestParsePreservesUnknownAlgorithms verifies non-success parser data.
func TestParsePreservesUnknownAlgorithms(t *testing.T) {
	value := signatureValueWith("s", testSelector+":future-sha999:"+base64OfByte(0xaa, 48))
	parsed, err := Parse(dkim2SignatureField(t, 0, value))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	sets := parsed.SignatureSets()
	if len(sets) != 1 {
		t.Fatalf("SignatureSets() length = %d, want 1", len(sets))
	}
	if sets[0].Algorithm() != "future-sha999" || sets[0].KnownAlgorithm() {
		t.Fatalf("unknown algorithm set = %#v", sets[0])
	}
	if sets[0].Signature().DecodedLen() != 48 {
		t.Fatalf("unknown signature decoded length = %d, want 48", sets[0].Signature().DecodedLen())
	}
}

// TestParseRejectsInvalidSignatureBase64AndLengths verifies s= base64 checks.
func TestParseRejectsInvalidSignatureBase64AndLengths(t *testing.T) {
	tests := []struct {
		name string
		in   string
		code ErrorCode
	}{
		{name: "invalid base64", in: testSelector + ":ed25519-sha256:not_base64", code: ErrorCodeInvalidSignatureBase64},
		{name: "ed25519 short", in: testSelector + ":ed25519-sha256:" + base64.StdEncoding.EncodeToString([]byte("short")), code: ErrorCodeInvalidSignatureLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("s", tt.in)))
			if !IsErrorCode(err, tt.code) {
				t.Fatalf("Parse() error = %v, want %s", err, tt.code)
			}
		})
	}
}

// TestParseRejectsDuplicateSignatureAlgorithmsAndSelectors verifies ambiguity handling.
func TestParseRejectsDuplicateSignatureAlgorithmsAndSelectors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		code ErrorCode
	}{
		{
			name: "duplicate algorithm",
			in:   testSelector + ":rsa-sha256:" + base64OfByte(0xaa, 64) + ", selector2:RSA-SHA256:" + base64OfByte(0xbb, 64),
			code: ErrorCodeDuplicateSignatureAlgorithm,
		},
		{
			name: "duplicate selector",
			in:   testSelector + ":rsa-sha256:" + base64OfByte(0xaa, 64) + ", Selector1:ed25519-sha256:" + base64OfByte(0xbb, 64),
			code: ErrorCodeDuplicateSelector,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("s", tt.in)))
			if !IsErrorCode(err, tt.code) {
				t.Fatalf("Parse() error = %v, want %s", err, tt.code)
			}
		})
	}
}

// TestParseRejectsInvalidNonce verifies n= printable ASCII and size limits.
func TestParseRejectsInvalidNonce(t *testing.T) {
	tests := []string{"bad\x01nonce", string(bytes.Repeat([]byte{'a'}, 65))}
	for _, value := range tests {
		t.Run("nonce", func(t *testing.T) {
			_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("n", value)))
			if !IsErrorCode(err, ErrorCodeInvalidNonce) {
				t.Fatalf("Parse() error = %v, want invalid nonce", err)
			}
		})
	}
}

// TestSignatureAccessorsReturnImmutableCopies verifies parsed state copying.
func TestSignatureAccessorsReturnImmutableCopies(t *testing.T) {
	parsed, err := Parse(dkim2SignatureField(t, 0, validSignatureValue()+"; n=nonce"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	sets := parsed.SignatureSets()
	sets[0] = Set{}
	if got := parsed.SignatureSets(); len(got) != 1 || got[0].Selector() != testSelector {
		t.Fatalf("SignatureSets() after mutation = %#v", got)
	}

	freshSets := parsed.SignatureSets()
	decoded := freshSets[0].Signature().Decoded()
	decoded[0] = 0
	if got := freshSets[0].Signature().Decoded(); bytes.Equal(got, decoded) {
		t.Fatalf("Signature().Decoded() reused mutable storage")
	}

	nonce, ok := parsed.Nonce()
	if !ok {
		t.Fatal("Nonce() missing")
	}
	nonce[0] = 'X'
	if got, _ := parsed.Nonce(); bytes.Equal(got, nonce) {
		t.Fatalf("Nonce() reused mutable storage")
	}
}

// TestSignatureErrorStringIsSecretSafe verifies diagnostics omit raw values.
func TestSignatureErrorStringIsSecretSafe(t *testing.T) {
	rawPath := "secret@example.test"
	rawSignature := "not_base64_secret"
	_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("mf", baseValue(rawPath))+"; x_ext=ok"))
	if err == nil {
		t.Fatal("Parse() succeeded, want invalid path")
	}
	message := err.Error()
	for _, forbidden := range []string{rawPath, "secret@example.test", rawSignature, baseValue(rawPath), testSelector} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error string leaked parser data %q in %q", forbidden, message)
		}
	}
}

// dkim2SignatureField constructs a synthetic DKIM2-Signature header field.
func dkim2SignatureField(t *testing.T, index int, value string) rawmsg.HeaderField {
	t.Helper()
	if !strings.HasSuffix(strings.TrimRight(value, " \t"), ";") {
		value += ";"
	}

	return headerField(t, index, "DKIM2-Signature", value)
}

// headerField constructs a synthetic rawmsg header field for parser tests.
func headerField(t *testing.T, index int, name string, value string) rawmsg.HeaderField {
	t.Helper()

	fieldValue := []byte(" " + value)
	field, err := rawmsg.NewHeaderField(index, []byte(name), fieldValue, fieldValue, []byte(name+": "+value+"\r\n"))
	if err != nil {
		t.Fatalf("NewHeaderField() error = %v", err)
	}

	return field
}

// validSignatureValue returns a complete synthetic DKIM2-Signature tag list.
func validSignatureValue() string {
	return strings.Join([]string{
		testSequenceTag,
		testInstanceTag,
		testTimestampTag,
		"mf=" + baseValue("<sender@example.test>"),
		"rt=" + baseValue("<user@example.net>"),
		testDomainTag,
		"s=" + testSelector + ":ed25519-sha256:" + base64OfByte(0xaa, 64),
	}, "; ")
}

// nextDomainSignatureValue returns a complete signature using only the nd= envelope form.
func nextDomainSignatureValue() string {
	return strings.Join([]string{
		testSequenceTag,
		testInstanceTag,
		testTimestampTag,
		"nd=Next.EXAMPLE",
		testDomainTag,
		"s=" + testSelector + ":ed25519-sha256:" + base64OfByte(0xaa, 64),
	}, "; ")
}

// signatureValueWith returns a valid field with one tag value replaced or appended.
func signatureValueWith(tag string, value string) string {
	parts := strings.Split(validSignatureValue(), "; ")
	for i, part := range parts {
		if strings.HasPrefix(part, tag+"=") {
			parts[i] = tag + "=" + value
			return strings.Join(parts, "; ")
		}
	}

	return validSignatureValue() + "; " + tag + "=" + value
}

// signatureValueWithout returns a valid field with one tag omitted.
func signatureValueWithout(tag string) string {
	parts := strings.Split(validSignatureValue(), "; ")
	filtered := parts[:0]
	for _, part := range parts {
		if strings.HasPrefix(part, tag+"=") {
			continue
		}
		filtered = append(filtered, part)
	}

	return strings.Join(filtered, "; ")
}

// baseValue returns a padded base64 string for value.
func baseValue(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

// base64OfByte returns a padded base64 string containing repeated byte data.
func base64OfByte(b byte, count int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, count))
}
