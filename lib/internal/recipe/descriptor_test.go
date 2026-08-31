package recipe

import (
	"bytes"
	"fmt"
	"testing"
)

// TestDescriptorIsDeterministicBoundedAndPrivacyMinimized locks the policy projection boundary.
func TestDescriptorIsDeterministicBoundedAndPrivacyMinimized(t *testing.T) {
	parser, err := NewParser(DefaultLimits())
	if err != nil {
		t.Fatalf("NewParser() error = %v", err)
	}
	plan, _, err := parser.Parse([]byte(`{"h":{"subject":[{"d":["private subject"]}],"x-trace":[{"c":[1,1]}]},"b":[{"d":["private body"]}]}`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	first := plan.Descriptor()
	second := plan.Descriptor()
	if !first.Valid() || first.BodyMode() != BodyModeSteps || !first.HasHeaderChanges() || first.ChangeCount() != 2 || first.AffectedHeaderCount() != 2 {
		t.Fatalf("Descriptor() = %#v", first)
	}
	if got := first.ChangeClasses(); len(got) != 2 || got[0] != ChangeClassBodyRewrite || got[1] != ChangeClassHeaderRewrite {
		t.Fatalf("ChangeClasses() = %#v", got)
	}
	if got := first.AffectedHeaders(); len(got) != 2 || got[0] != testRecipeHeaderName || got[1] != "x-trace" {
		t.Fatalf("AffectedHeaders() = %#v", got)
	}
	if first.Digest() != second.Digest() {
		t.Fatal("descriptor digest is nondeterministic")
	}
	exposed := first.AffectedHeaders()
	exposed[0] = "mutated"
	if first.AffectedHeaders()[0] != testRecipeHeaderName {
		t.Fatal("descriptor header names are mutable")
	}
	formatted := fmt.Sprintf("%#v %s", first, first)
	digest := first.Digest()
	for _, secret := range [][]byte{[]byte("private subject"), []byte("private body")} {
		if bytes.Contains([]byte(formatted), secret) || bytes.Contains(digest[:], secret) {
			t.Fatalf("descriptor exposed recipe literal of %d bytes", len(secret))
		}
	}
}

// TestDescriptorDistinguishesClosedRecipeShapes locks exact canonical framing inputs.
func TestDescriptorDistinguishesClosedRecipeShapes(t *testing.T) {
	parser, err := NewParser(DefaultLimits())
	if err != nil {
		t.Fatalf("NewParser() error = %v", err)
	}
	inputs := [][]byte{
		[]byte(`{"h":{"subject":[]}}`),
		[]byte(`{"b":[]}`),
		[]byte(`{"b":null}`),
	}
	seen := make(map[[32]byte]bool, len(inputs))
	for _, input := range inputs {
		plan, _, parseErr := parser.Parse(input)
		if parseErr != nil {
			t.Fatalf("Parse() error = %v", parseErr)
		}
		descriptor := plan.Descriptor()
		if !descriptor.Valid() || seen[descriptor.Digest()] {
			t.Fatalf("Descriptor() invalid or collided for %d-byte input", len(input))
		}
		seen[descriptor.Digest()] = true
	}
	if (Descriptor{}).Valid() || ChangeClass("future").Known() {
		t.Fatal("zero or future descriptor state accepted")
	}
}
