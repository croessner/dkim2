package wire

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestProtectedStringTransport exercises exact JSON and accessor round trips.
func TestProtectedStringTransport(t *testing.T) {
	t.Parallel()

	const protected = "<δοκιμή@example.test>"
	value, err := NewProtectedString(protected)
	if err != nil {
		t.Fatalf("construct protected string: %v", err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal protected string: %v", err)
	}
	var transported string
	if err := json.Unmarshal(encoded, &transported); err != nil {
		t.Fatalf("decode marshaled protected string: %v", err)
	}
	if transported != protected {
		t.Fatal("marshaled value differs")
	}

	var decoded ProtectedString
	if err := json.Unmarshal([]byte(`"\u003c\u03b4\u003e"`), &decoded); err != nil {
		t.Fatalf("unmarshal escaped protected string: %v", err)
	}
	got, err := decoded.Bytes()
	if err != nil {
		t.Fatalf("access protected string: %v", err)
	}
	if string(got) != "<δ>" {
		t.Fatal("decoded bytes differ")
	}
}

// TestProtectedStringRejectsInvalidStateAndJSON verifies fail-closed zero-value
// and malformed-scalar behavior.
func TestProtectedStringRejectsInvalidStateAndJSON(t *testing.T) {
	t.Parallel()

	var zero ProtectedString
	if _, err := zero.Bytes(); err == nil {
		t.Fatal("zero-value accessor unexpectedly succeeded")
	}
	if _, err := json.Marshal(zero); err == nil {
		t.Fatal("zero-value marshal unexpectedly succeeded")
	}

	invalid := [][]byte{
		[]byte("null"),
		[]byte("false"),
		[]byte(`"\ud800"`),
		[]byte(`"\udc00"`),
		[]byte(`"\ud800\u0041"`),
		[]byte{'"', 0xff, '"'},
		[]byte{'"', '\r', '"'},
	}
	for _, input := range invalid {
		value, err := NewProtectedString("prior secret")
		if err != nil {
			t.Fatalf("construct initial value: %v", err)
		}
		if err := value.UnmarshalJSON(input); err == nil {
			t.Fatalf("unmarshal %q unexpectedly succeeded", input)
		}
		if _, err := value.Bytes(); err == nil {
			t.Fatalf("failed unmarshal %q retained prior value", input)
		}
	}
}

// TestProtectedStringFormattingIsContentFree proves common diagnostic verbs
// cannot reveal a valid or invalid wrapper value.
func TestProtectedStringFormattingIsContentFree(t *testing.T) {
	t.Parallel()

	const marker = "DO-NOT-PRINT-SMTP-PATH"
	valid, err := NewProtectedString(marker)
	if err != nil {
		t.Fatalf("construct protected string: %v", err)
	}
	var invalid ProtectedString

	formats := []string{"%s", "%q", "%v", "%+v", "%#v", "%x", "%p"}
	values := []any{valid, &valid, invalid, &invalid}
	for _, format := range formats {
		for _, value := range values {
			formatted := fmt.Sprintf(format, value)
			if format != "%p" && formatted != protectedFormattingValue {
				t.Fatalf("format %q produced a noncanonical protected value", format)
			}
			if strings.Contains(formatted, marker) ||
				strings.Contains(formatted, fmt.Sprintf("%x", []byte(marker))) {
				t.Fatalf("format %q revealed a protected marker", format)
			}
		}
	}
}

// TestProtectedStringAccessorReturnsACopy proves callers cannot mutate the
// immutable state through the byte accessor.
func TestProtectedStringAccessorReturnsACopy(t *testing.T) {
	t.Parallel()

	value, err := NewProtectedString("secret")
	if err != nil {
		t.Fatalf("construct protected string: %v", err)
	}
	first, err := value.Bytes()
	if err != nil {
		t.Fatalf("first access: %v", err)
	}
	first[0] = 'X'
	second, err := value.Bytes()
	if err != nil {
		t.Fatalf("second access: %v", err)
	}
	if string(second) != "secret" {
		t.Fatal("accessor exposed mutable backing state")
	}
}
