package domainname

import (
	"strings"
	"testing"
)

const testALabelDomain = "xn--bcher-kva.example"

// TestToASCIIConvertsValidLabels reproduces the Draft-08 Section 18 U-label to
// A-label mapping, A-label round trips, and ASCII case folding.
func TestToASCIIConvertsValidLabels(t *testing.T) {
	for input, want := range map[string]string{
		"example.test":          "example.test",
		"Mail.EXAMPLE.Test":     "mail.example.test",
		"bücher.example":        testALabelDomain,
		testALabelDomain:        testALabelDomain,
		"XN--BCHER-KVA.example": testALabelDomain,
		"straße.example":        "xn--strae-oqa.example",
		"例え.テスト":                "xn--r8jz45g.xn--zckzah",
	} {
		got, ok := ToASCII([]byte(input))
		if !ok || got != want {
			t.Fatalf("ToASCII(%q) = %q/%t, want %q", input, got, ok, want)
		}
	}
}

// TestToASCIIRejectsInvalidAndMappedInput reproduces the D4 strict profile:
// no compatibility mapping, NFC required, IDNA2008 context and Bidi rules, and
// DNS structure limits.
func TestToASCIIRejectsInvalidAndMappedInput(t *testing.T) {
	for name, input := range map[string]string{
		"empty":             "",
		"trailing dot":      "example.test.",
		"leading dot":       ".example.test",
		"empty label":       "a..example",
		"non nfc":           "bücher.example",
		"fullwidth":         "ｅｘａｍｐｌｅ.test",
		"ideographic dot":   "example。test",
		"uppercase u-label": "bÜcher.example",
		"invalid punycode":  "xn--a.example",
		"bad a-label":       "xn--bcher-kvb.example",
		"zero width joiner": "a\u200db.example",
		"bidi mix":          "אa.example",
		"leading hyphen":    "-example.test",
		"underscore":        "ex_ample.test",
		"label too long":    strings.Repeat("a", 64) + ".test",
		"name too long":     strings.Repeat(strings.Repeat("a", 63)+".", 4) + "test",
		"literal":           "[192.0.2.1]",
		"invalid utf8":      "\xff.example",
	} {
		if got, ok := ToASCII([]byte(input)); ok || got != "" {
			t.Fatalf("%s: ToASCII(%q) = %q/%t, want rejection without output", name, input, got, ok)
		}
	}
}

// TestIsASCII distinguishes recorded A-label form from U-label input.
func TestIsASCII(t *testing.T) {
	if !IsASCII([]byte(testALabelDomain)) || IsASCII([]byte("bücher.example")) {
		t.Fatal("IsASCII misclassified domain form")
	}
}
