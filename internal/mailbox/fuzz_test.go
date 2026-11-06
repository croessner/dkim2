package mailbox

import "testing"

// FuzzParseAuthor proves bounded, panic-free classification of arbitrary
// author values and that a single result always carries a nonempty domain.
func FuzzParseAuthor(f *testing.F) {
	for _, seed := range []string{
		"user@example.test", "Name <a@b.example>", "G: a@b.example;", "(c (d)) \"q\\\"x\"@b.example",
		"a@[192.0.2.1]", "Grüße <jörg@bücher.example>", "a@b,c@d", "<@r:a@b.example>",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		author, status := ParseAuthor(value)
		if status == StatusSingle && author.Domain() == "" || status != StatusSingle && author.Domain() != "" {
			t.Fatalf("inconsistent result status=%s", status)
		}
	})
}
