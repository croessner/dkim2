package tagvalue

import "testing"

// TestParseTextstringPreservesCase reproduces the Draft-08 Section 2.14 rule
// that textstring values are case-sensitive and never folded.
func TestParseTextstringPreservesCase(t *testing.T) {
	for _, input := range []string{"sha256", "SHA256", "rsa-sha256", "Exploded", "x_1-y"} {
		got, ok := ParseTextstring([]byte(input))
		if !ok || got != input {
			t.Fatalf("ParseTextstring(%q) = %q/%t, want unchanged", input, got, ok)
		}
	}
	for _, input := range []string{"", "a b", "a:b", "a,b", "ä", "a;"} {
		if _, ok := ParseTextstring([]byte(input)); ok {
			t.Fatalf("ParseTextstring(%q) accepted invalid textstring", input)
		}
	}
}
