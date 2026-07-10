package tagvalue

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzScanTagList smoke-tests shared tag-list parsing with bounded inputs.
func FuzzScanTagList(f *testing.F) {
	seeds := [][]byte{
		[]byte("m=1; h=sha256; x_ext=ignored;"),
		[]byte("M=1; H=ValueWithCASE;"),
		[]byte("m=1;;h=abc;"),
		[]byte("x_ext=private-token-value; X_Ext=again;"),
		[]byte("bad-name=secret.example.test;"),
		[]byte("m=1; h=missing-final-terminator"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	known := MustKnownTags("m", "h", "r", "empty")
	limits := Limits{
		MaxFieldValueBytes:    256,
		MaxTags:               16,
		MaxTagNameBytes:       32,
		MaxTagValueBytes:      128,
		MaxBase64DecodedBytes: 128,
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		before := bytes.Clone(input)
		_, err := Scan(input, known, limits)
		_, repeatedErr := Scan(bytes.Clone(before), known, limits)
		if !bytes.Equal(input, before) {
			t.Fatal("Scan mutated caller-owned input")
		}
		assertSameTagvalueFuzzClassification(t, err, repeatedErr)
		assertNoFuzzSecretLeak(t, err, before)
	})
}

// assertSameTagvalueFuzzClassification checks deterministic success and typed error facts.
func assertSameTagvalueFuzzClassification(t *testing.T, first error, second error) {
	t.Helper()
	if (first == nil) != (second == nil) {
		t.Fatalf("repeated Scan success differs: first=%v second=%v", first, second)
	}
	if first == nil {
		return
	}
	firstTyped, firstOK := first.(*Error)
	secondTyped, secondOK := second.(*Error)
	if !firstOK || !secondOK {
		t.Fatalf("repeated Scan returned untyped errors: first=%T second=%T", first, second)
	}
	if firstTyped.Code() != secondTyped.Code() || firstTyped.Class() != secondTyped.Class() {
		t.Fatalf("repeated Scan classification differs: first=%s/%s second=%s/%s",
			firstTyped.Code(), firstTyped.Class(), secondTyped.Code(), secondTyped.Class())
	}
}

// assertNoFuzzSecretLeak verifies diagnostics omit synthetic toxic markers.
func assertNoFuzzSecretLeak(t *testing.T, err error, input []byte) {
	t.Helper()
	if err == nil {
		return
	}

	message := err.Error()
	for _, marker := range []string{"secret.example.test", "private-token-value", "nonce-secret", "hash-secret", "signature-secret"} {
		if bytes.Contains(input, []byte(marker)) && strings.Contains(message, marker) {
			t.Fatalf("error string leaked fuzz marker %q in %q", marker, message)
		}
	}
}
