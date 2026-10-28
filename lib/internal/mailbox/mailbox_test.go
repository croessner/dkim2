package mailbox

import (
	"strings"
	"testing"
)

const testDomain = "example.test"

// TestParseAuthorAcceptsSingleMailboxForms covers the RFC 5322, RFC 6532,
// and RFC 6854 forms accepted for one author mailbox.
func TestParseAuthorAcceptsSingleMailboxForms(t *testing.T) {
	tests := []struct {
		value, local, domain string
		group, ascii         bool
	}{
		{"user@example.test", "user", testDomain, false, true},
		{"User Name <User@Example.TEST>", "User", testDomain, false, true},
		{"\"Doe, John\" <john.doe@sub.example.test>", "john.doe", "sub.example.test", false, true},
		{"(comment) <a@example.test> (trailing)", "a", testDomain, false, true},
		{"\"quoted local\"@example.test", "\"quoted local\"", testDomain, false, true},
		{"Joe Q. Public <joe@example.test>", "joe", testDomain, false, true},
		{"Team: member@example.test;", "member", "example.test", true, true},
		{"Grüße <jörg@bücher.example>", "jörg", "xn--bcher-kva.example", false, false},
		{"first.last@example.test", "first.last", testDomain, false, true},
		{"Undisclosed: ; , solo@example.test", "solo", testDomain, false, true},
	}
	for _, test := range tests {
		author, status := ParseAuthor([]byte(test.value))
		if status != StatusSingle || author.LocalPart() != test.local || author.Domain() != test.domain || author.InGroup() != test.group || author.ASCII() != test.ascii {
			t.Fatalf("ParseAuthor(%q) = %+v/%s", test.value, author, status)
		}
	}
}

// TestParseAuthorClassifiesNonAuthenticForms reproduces the Draft-08 Section
// 11 rule that multiple addresses and domain literals can never be Authentic.
func TestParseAuthorClassifiesNonAuthenticForms(t *testing.T) {
	tests := map[string]Status{
		"a@example.test, b@example.test":        StatusMultiple,
		"Team: a@example.test, b@example.test;": StatusMultiple,
		"Team: ;":                               StatusNoMailbox,
		"user@[192.0.2.1]":                      StatusDomainLiteral,
		"user@ex_ample.test":                    StatusInvalidDomain,
		"user@bücher.example":                  StatusInvalidDomain,
		"":                                      StatusMalformed,
		"no-at-sign":                            StatusMalformed,
		"<@route.example:user@example.test>":    StatusMalformed,
		"a@example.test,":                       StatusMalformed,
		"a@example.test,, b@example.test":       StatusMalformed,
		"Team: a@example.test":                  StatusMalformed,
		"Outer: Inner: a@example.test;;":        StatusMalformed,
		"\"unterminated@example.test":           StatusMalformed,
		"(open comment a@example.test":          StatusMalformed,
		"a@example.test\r\n":                    StatusMalformed,
		"\xff@example.test":                     StatusMalformed,
		"user.@example.test":                    StatusMalformed,
	}
	for value, want := range tests {
		if author, status := ParseAuthor([]byte(value)); status != want || author.Domain() != "" {
			t.Fatalf("ParseAuthor(%q) status=%s, want %s", value, status, want)
		}
	}
	if _, status := ParseAuthor([]byte(strings.Repeat("a", MaxValueBytes+1))); status != StatusMalformed {
		t.Fatalf("oversized value status=%s", status)
	}
}
