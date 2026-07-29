package strictjson

import (
	"strings"
	"testing"
)

type fixture struct {
	Outer struct {
		Name string `json:"name"`
	} `json:"outer"`
}

// TestDecodeRejectsDuplicateUnknownTrailingAndDeepInput freezes strict evidence JSON.
func TestDecodeRejectsDuplicateUnknownTrailingAndDeepInput(t *testing.T) {
	tests := []string{
		`{"outer":{"name":"first","name":"second"}}`,
		`{"outer":{"name":"first","unknown":true}}`,
		`{"outer":{"name":"first"}} {}`,
		`{"outer":{"name":{"deep":true}}}`,
	}
	for _, input := range tests {
		var value fixture
		if err := Decode([]byte(input), &value, 2, 32); err == nil {
			t.Fatalf("hostile JSON was accepted: %s", input)
		}
	}
}

// TestDecodeAcceptsOneClosedDocument proves the positive strict contract.
func TestDecodeAcceptsOneClosedDocument(t *testing.T) {
	var value fixture
	if err := Decode([]byte(`{"outer":{"name":"safe"}}`), &value, 4, 32); err != nil {
		t.Fatal(err)
	}
	if value.Outer.Name != "safe" {
		t.Fatalf("name = %q", value.Outer.Name)
	}
}

// FuzzDecodeNeverPanicsOrChangesClassification exercises the shared bounded
// evidence parser against arbitrary duplicate, deep, malformed, and trailing
// JSON bytes.
func FuzzDecodeNeverPanicsOrChangesClassification(f *testing.F) {
	f.Add([]byte(`{"outer":{"name":"safe"}}`))
	f.Add([]byte(`{"outer":{"name":"first","name":"second"}}`))
	f.Add([]byte(`{"outer":{"name":"safe"}} {}`))
	f.Add([]byte(strings.Repeat(`[`, 64) + strings.Repeat(`]`, 64)))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			input = input[:4096]
		}
		var first fixture
		firstErr := Decode(input, &first, 4, 64)
		var second fixture
		secondErr := Decode(input, &second, 4, 64)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatal("strict JSON classification changed for identical bytes")
		}
		if firstErr == nil && first != second {
			t.Fatal("strict JSON projection changed for identical bytes")
		}
		if string(input) == `{"outer":{"name":"safe"}}` &&
			(firstErr != nil || first.Outer.Name != "safe") {
			t.Fatal("known-valid strict JSON was rejected")
		}
	})
}
