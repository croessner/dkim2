package canonical

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// FuzzBodyHashInput exercises Section 6.1 canonicalization with bounded body bytes.
func FuzzBodyHashInput(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte{},
		[]byte("alpha"),
		[]byte("alpha\r\n"),
		[]byte("alpha\r\n\r\n\r\n"),
		[]byte("Content-Type: text/plain\r\n\r\nnot decoded=3Dyes\r\n"),
		{0xff, 0x00, 0x80, 't', 'a', 'i', 'l'},
	} {
		f.Add(seed)
	}

	canonicalizer := mustFuzzCanonicalizer(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		body := fuzzBodyBytes(input)
		originalBody := bytes.Clone(body)
		msg := mustParseBodyMessage(t, body)

		got, err := canonicalizer.BodyHashInputFromMessage(msg)
		if err != nil {
			assertCanonicalFuzzError(t, err, body)
			return
		}
		assertFuzzBytesUnmutated(t, body, originalBody, "body input")
		assertFuzzByteInputImmutable(t, got)
		if !bytes.HasSuffix(got.Bytes(), canonicalBodyCRLF) {
			t.Fatalf("BodyHashInputFromMessage() output lacks terminal CRLF")
		}
	})
}

// FuzzHeaderHashInput exercises Section 6.2 canonicalization with synthetic headers.
func FuzzHeaderHashInput(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("Alpha Beta"),
		[]byte("folded\tvalue"),
		[]byte("synthetic-marker"),
		[]byte(""),
	} {
		f.Add(seed)
	}

	canonicalizer := mustFuzzCanonicalizer(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		value := fuzzHeaderValue(input)
		headers := []byte("Received: excluded\r\nSubject: " + value + "\r\nsubject:\tSecond " + value + "\r\nEmpty:\r\n")
		originalHeaders := bytes.Clone(headers)
		msg := mustParseHeaderMessage(t, headers)

		got, err := canonicalizer.HeaderHashInputFromMessage(msg)
		if err != nil {
			assertCanonicalFuzzError(t, err, headers)
			return
		}
		assertFuzzBytesUnmutated(t, headers, originalHeaders, "header input")
		assertFuzzByteInputImmutable(t, got)
		if got.Metadata().Kind != KindHeaderHashInput || got.Metadata().Draft != DraftBaseline {
			t.Fatalf("HeaderHashInputFromMessage() metadata = %#v, want draft header metadata", got.Metadata())
		}
	})
}

// FuzzSignatureInput exercises Section 9.6 canonicalization with parser-owned DKIM2 fields.
func FuzzSignatureInput(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("alpha beta"),
		[]byte("synthetic-marker"),
		[]byte("\twith wsp"),
		[]byte(""),
	} {
		f.Add(seed)
	}

	canonicalizer := mustFuzzCanonicalizer(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		token := fuzzTagText(input)
		headers := []byte(messageInstanceLine(1, token) +
			signatureLine(1, "sel-a:rsa-sha256:"+base64Text("synthetic signature"), " x="+token+";\r\n"))
		originalHeaders := bytes.Clone(headers)
		msg := mustParseHeaderMessage(t, headers)

		got, err := canonicalizer.SignatureInputFromMessage(msg, 1)
		if err != nil {
			assertCanonicalFuzzError(t, err, headers)
			return
		}
		assertFuzzBytesUnmutated(t, headers, originalHeaders, "signature input")
		assertFuzzByteInputImmutable(t, got)
		if bytes.ContainsAny(got.Bytes(), " \t") {
			t.Fatalf("SignatureInputFromMessage() retained WSP")
		}
	})
}

// mustFuzzCanonicalizer constructs a canonicalizer with small deterministic limits.
func mustFuzzCanonicalizer(f *testing.F) Canonicalizer {
	f.Helper()

	limits := DefaultLimits()
	limits.MaxBodyInputBytes = 512
	limits.MaxHeaderInputBytes = 1024
	limits.MaxSignatureInputBytes = 2048
	limits.MaxFieldBytes = 1024
	limits.MaxFieldCount = 16
	canonicalizer, err := NewCanonicalizer(WithLimits(limits))
	if err != nil {
		f.Fatalf("NewCanonicalizer() error = %v", err)
	}

	return canonicalizer
}

// fuzzBodyBytes maps arbitrary input to strict-CRLF-safe body bytes.
func fuzzBodyBytes(input []byte) []byte {
	if len(input) > 256 {
		input = input[:256]
	}

	body := bytes.Clone(input)
	for i, b := range body {
		if b == '\r' || b == '\n' {
			body[i] = '.'
		}
	}

	return body
}

// fuzzHeaderValue maps arbitrary input to one unfolded header value.
func fuzzHeaderValue(input []byte) string {
	if len(input) > 128 {
		input = input[:128]
	}

	var builder strings.Builder
	for _, b := range input {
		switch {
		case b == '\r' || b == '\n' || b == 0:
			builder.WriteByte('.')
		case b == '\t':
			builder.WriteByte('\t')
		case b < 0x20 || b > 0x7e:
			builder.WriteByte('x')
		default:
			builder.WriteByte(b)
		}
	}

	return builder.String()
}

// fuzzTagText maps arbitrary input to a DKIM2 extension value safe for parsing.
func fuzzTagText(input []byte) string {
	if len(input) > 64 {
		input = input[:64]
	}

	var builder strings.Builder
	for _, b := range input {
		switch {
		case b == ' ' || b == '\t':
			builder.WriteByte(b)
		case b >= 'a' && b <= 'z':
			builder.WriteByte(b)
		case b >= 'A' && b <= 'Z':
			builder.WriteByte(b)
		case b >= '0' && b <= '9':
			builder.WriteByte(b)
		case b == '-' || b == '_':
			builder.WriteByte(b)
		default:
			builder.WriteByte('x')
		}
	}
	if builder.Len() == 0 {
		return "empty"
	}

	return builder.String()
}

// assertCanonicalFuzzError verifies canonicalization errors stay typed and secret-safe.
func assertCanonicalFuzzError(t *testing.T, err error, input []byte) {
	t.Helper()

	var canonicalErr *Error
	if !errors.As(err, &canonicalErr) {
		t.Fatalf("canonical fuzz error = %T, want *Error", err)
	}
	message := err.Error()
	for _, marker := range []string{"synthetic-marker", "private-token-value"} {
		if bytes.Contains(input, []byte(marker)) && strings.Contains(message, marker) {
			t.Fatalf("canonical error leaked marker %q in %q", marker, message)
		}
	}
}

// assertFuzzBytesUnmutated verifies canonicalization did not mutate caller input.
func assertFuzzBytesUnmutated(t *testing.T, got []byte, want []byte, label string) {
	t.Helper()

	if !bytes.Equal(got, want) {
		t.Fatalf("%s was mutated during canonicalization", label)
	}
}

// assertFuzzByteInputImmutable verifies returned canonical bytes are accessor-immutable.
func assertFuzzByteInputImmutable(t *testing.T, input ByteInput) {
	t.Helper()

	before := input.Bytes()
	exposed := input.Bytes()
	if len(exposed) > 0 {
		exposed[0] ^= 0xff
	}
	if !bytes.Equal(input.Bytes(), before) {
		t.Fatal("canonical bytes changed after accessor mutation")
	}
}
