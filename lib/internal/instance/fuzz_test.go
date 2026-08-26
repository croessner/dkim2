package instance

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/tagvalue"
)

// FuzzParseMessageInstance smoke-tests Message-Instance parsing with bounded inputs.
func FuzzParseMessageInstance(f *testing.F) {
	seeds := [][]byte{
		[]byte("m=1; h=sha256:" + base64OfByte(0x11, 32) + ":" + base64OfByte(0x22, 32) + ";"),
		[]byte("m=1; h=sha512:" + base64OfByte(0x11, 64) + ":" + base64OfByte(0x22, 64) + ";"),
		[]byte("m=1; h=future-hash:" + base64OfByte(0x11, 8) + ":" + base64OfByte(0x22, 8) + ",FUTURE-HASH:" + base64OfByte(0x33, 8) + ":" + base64OfByte(0x44, 8) + ";"),
		[]byte("m=0; h=sha256:" + base64OfByte(0x11, 32) + ":" + base64OfByte(0x22, 32) + ";"),
		[]byte("m=1; h=sha256:not_base64:" + base64OfByte(0x22, 32) + ";"),
		[]byte("m=1; h=sha256:" + base64OfByte(0x11, 32) + ":" + base64OfByte(0x22, 32) + "; r=c2VjcmV0LXJlY2lwZQ;"),
		[]byte("m=1; h=missing-final-terminator"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	parser, err := NewParser(Limits{
		TagLimits: tagvalue.Limits{
			MaxFieldValueBytes:    512,
			MaxTags:               16,
			MaxTagNameBytes:       32,
			MaxTagValueBytes:      256,
			MaxBase64DecodedBytes: 256,
		},
		MaxHashSets: 8,
	})
	if err != nil {
		f.Fatalf("NewParser() error = %v", err)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		before := bytes.Clone(input)
		field, constructionErr := fuzzHeaderField(t, HeaderName, before)
		repeatedField, repeatedConstructionErr := fuzzHeaderField(t, HeaderName, bytes.Clone(before))
		assertSameRawmsgFuzzClassification(t, constructionErr, repeatedConstructionErr)
		if constructionErr != nil {
			if !bytes.Equal(input, before) {
				t.Fatal("HeaderField construction mutated caller-owned input")
			}
			assertNoInstanceFuzzSecretLeak(t, constructionErr, before)

			return
		}
		_, parseErr := parser.ParseField(field)
		_, repeatedErr := parser.ParseField(repeatedField)
		if !bytes.Equal(input, before) {
			t.Fatal("ParseField mutated caller-owned input")
		}
		assertSameInstanceFuzzClassification(t, parseErr, repeatedErr)
		assertNoInstanceFuzzSecretLeak(t, parseErr, before)
	})
}

// assertSameInstanceFuzzClassification checks deterministic success and typed error facts.
func assertSameInstanceFuzzClassification(t *testing.T, first error, second error) {
	t.Helper()
	if (first == nil) != (second == nil) {
		t.Fatalf("repeated ParseField success differs: first=%v second=%v", first, second)
	}
	if first == nil {
		return
	}
	firstSource, firstCode, firstClass := instanceFuzzClassification(t, first)
	secondSource, secondCode, secondClass := instanceFuzzClassification(t, second)
	if firstSource != secondSource || firstCode != secondCode || firstClass != secondClass {
		t.Fatalf("repeated ParseField classification differs: first=%s/%s/%s second=%s/%s/%s",
			firstSource, firstCode, firstClass, secondSource, secondCode, secondClass)
	}
}

// instanceFuzzClassification returns the typed parser layer, code, and class.
func instanceFuzzClassification(t *testing.T, err error) (string, string, string) {
	t.Helper()
	var instanceErr *Error
	if errors.As(err, &instanceErr) {
		return "instance", string(instanceErr.Code()), string(instanceErr.Class())
	}
	var tagErr *tagvalue.Error
	if errors.As(err, &tagErr) {
		return "tagvalue", string(tagErr.Code()), string(tagErr.Class())
	}

	t.Fatalf("ParseField returned untyped error %T", err)
	return "", "", ""
}

// fuzzHeaderField constructs a parser-owned rawmsg header field from fuzz bytes.
func fuzzHeaderField(t *testing.T, name string, value []byte) (rawmsg.HeaderField, error) {
	t.Helper()

	rawName := []byte(name)
	rawValue := append([]byte{' '}, value...)
	original := make([]byte, 0, len(rawName)+2+len(value)+2)
	original = append(original, rawName...)
	original = append(original, ':', ' ')
	original = append(original, value...)
	original = append(original, '\r', '\n')

	field, err := rawmsg.NewHeaderField(0, rawName, rawValue, rawValue, original)
	if err != nil {
		return rawmsg.HeaderField{}, err
	}

	return field, nil
}

// assertSameRawmsgFuzzClassification checks deterministic HeaderField construction failures.
func assertSameRawmsgFuzzClassification(t *testing.T, first error, second error) {
	t.Helper()
	if (first == nil) != (second == nil) {
		t.Fatalf("repeated HeaderField construction differs: first=%v second=%v", first, second)
	}
	if first == nil {
		return
	}
	var firstTyped *rawmsg.ParserError
	var secondTyped *rawmsg.ParserError
	if !errors.As(first, &firstTyped) || !errors.As(second, &secondTyped) {
		t.Fatalf("HeaderField construction returned untyped errors: first=%T second=%T", first, second)
	}
	if firstTyped.Code() != secondTyped.Code() || firstTyped.ReasonClass() != secondTyped.ReasonClass() {
		t.Fatalf("repeated HeaderField classification differs: first=%s/%s second=%s/%s",
			firstTyped.Code(), firstTyped.ReasonClass(), secondTyped.Code(), secondTyped.ReasonClass())
	}
}

// assertNoInstanceFuzzSecretLeak verifies diagnostics omit synthetic toxic markers.
func assertNoInstanceFuzzSecretLeak(t *testing.T, err error, input []byte) {
	t.Helper()
	if err == nil {
		return
	}

	message := err.Error()
	for _, marker := range []string{"secret-recipe", "hash-secret", "private-token-value"} {
		if bytes.Contains(input, []byte(marker)) && strings.Contains(message, marker) {
			t.Fatalf("error string leaked fuzz marker %q in %q", marker, message)
		}
	}
}
