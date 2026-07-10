package signature

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/tagvalue"
)

// FuzzParseDKIM2Signature smoke-tests DKIM2-Signature parsing with bounded inputs.
func FuzzParseDKIM2Signature(f *testing.F) {
	seeds := [][]byte{
		[]byte(validSignatureValue() + ";"),
		[]byte(nextDomainSignatureValue() + ";"),
		[]byte(signatureValueWith("f", "feedhere") + ";"),
		[]byte(signatureValueWith("mf", baseValue("secret.example.test")) + ";"),
		[]byte(signatureValueWith("rt", baseValue("<user@example.test>")+","+baseValue("<second@example.test>")) + ";"),
		[]byte(signatureValueWith("s", "selector1:future-sha999:"+base64OfByte(0xbb, 48)) + ";"),
		[]byte(signatureValueWith("n", "nonce-secret;bad") + ";"),
		[]byte(validSignatureValue()),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	parser, err := NewParser(Limits{
		TagLimits: tagvalue.Limits{
			MaxFieldValueBytes:    1024,
			MaxTags:               16,
			MaxTagNameBytes:       32,
			MaxTagValueBytes:      512,
			MaxBase64DecodedBytes: 512,
		},
		MaxRecipients:    8,
		MaxSignatureSets: 8,
		MaxFlags:         8,
		MaxNonceBytes:    64,
	})
	if err != nil {
		f.Fatalf("NewParser() error = %v", err)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		before := bytes.Clone(input)
		field, constructionErr := fuzzSignatureHeaderField(t, before)
		repeatedField, repeatedConstructionErr := fuzzSignatureHeaderField(t, bytes.Clone(before))
		assertSameSignatureRawmsgFuzzClassification(t, constructionErr, repeatedConstructionErr)
		if constructionErr != nil {
			if !bytes.Equal(input, before) {
				t.Fatal("HeaderField construction mutated caller-owned input")
			}
			assertNoSignatureFuzzSecretLeak(t, constructionErr, before)

			return
		}
		_, parseErr := parser.ParseField(field)
		_, repeatedErr := parser.ParseField(repeatedField)
		if !bytes.Equal(input, before) {
			t.Fatal("ParseField mutated caller-owned input")
		}
		assertSameSignatureFuzzClassification(t, parseErr, repeatedErr)
		assertNoSignatureFuzzSecretLeak(t, parseErr, before)
	})
}

// assertSameSignatureFuzzClassification checks deterministic success and typed error facts.
func assertSameSignatureFuzzClassification(t *testing.T, first error, second error) {
	t.Helper()
	if (first == nil) != (second == nil) {
		t.Fatalf("repeated ParseField success differs: first=%v second=%v", first, second)
	}
	if first == nil {
		return
	}
	firstSource, firstCode, firstClass := signatureFuzzClassification(t, first)
	secondSource, secondCode, secondClass := signatureFuzzClassification(t, second)
	if firstSource != secondSource || firstCode != secondCode || firstClass != secondClass {
		t.Fatalf("repeated ParseField classification differs: first=%s/%s/%s second=%s/%s/%s",
			firstSource, firstCode, firstClass, secondSource, secondCode, secondClass)
	}
}

// signatureFuzzClassification returns the typed parser layer, code, and class.
func signatureFuzzClassification(t *testing.T, err error) (string, string, string) {
	t.Helper()
	var signatureErr *Error
	if errors.As(err, &signatureErr) {
		return "signature", string(signatureErr.Code()), string(signatureErr.Class())
	}
	var tagErr *tagvalue.Error
	if errors.As(err, &tagErr) {
		return "tagvalue", string(tagErr.Code()), string(tagErr.Class())
	}

	t.Fatalf("ParseField returned untyped error %T", err)
	return "", "", ""
}

// fuzzSignatureHeaderField constructs a parser-owned DKIM2-Signature field.
func fuzzSignatureHeaderField(t *testing.T, value []byte) (rawmsg.HeaderField, error) {
	t.Helper()

	rawName := []byte("DKIM2-Signature")
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

// assertSameSignatureRawmsgFuzzClassification checks deterministic HeaderField construction failures.
func assertSameSignatureRawmsgFuzzClassification(t *testing.T, first error, second error) {
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

// assertNoSignatureFuzzSecretLeak verifies diagnostics omit synthetic toxic markers.
func assertNoSignatureFuzzSecretLeak(t *testing.T, err error, input []byte) {
	t.Helper()
	if err == nil {
		return
	}

	message := err.Error()
	for _, marker := range []string{"secret.example.test", "nonce-secret", "signature-secret", "private-token-value"} {
		if bytes.Contains(input, []byte(marker)) && strings.Contains(message, marker) {
			t.Fatalf("error string leaked fuzz marker %q in %q", marker, message)
		}
	}
}
