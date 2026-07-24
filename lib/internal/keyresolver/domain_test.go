package keyresolver

import (
	"strings"
	"testing"
)

const shortSigningDomain = "a.test"

// TestCanonicalSigningDomainValidatesExactASCIIBounds verifies the shared domain seam at every hard edge.
func TestCanonicalSigningDomainValidatesExactASCIIBounds(t *testing.T) {
	exactBytes := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 61),
	}, ".")
	if len(exactBytes) != 253 {
		t.Fatalf("exact byte fixture length = %d", len(exactBytes))
	}
	exactLabels := strings.Repeat("a.", 126) + "a"
	if len(strings.Split(exactLabels, ".")) != 127 || len(exactLabels) != 253 {
		t.Fatalf("exact label fixture labels=%d bytes=%d", len(strings.Split(exactLabels, ".")), len(exactLabels))
	}

	tests := []struct {
		name      string
		value     string
		maxBytes  int
		maxLabels int
		want      string
	}{
		{name: "uppercase canonical", value: "Mail.Example.TEST", maxBytes: 253, maxLabels: 127, want: "mail.example.test"},
		{name: "exact bytes", value: exactBytes, maxBytes: 253, maxLabels: 127, want: exactBytes},
		{name: "exact labels", value: exactLabels, maxBytes: 253, maxLabels: 127, want: exactLabels},
		{name: "exact narrow bytes", value: shortSigningDomain, maxBytes: 6, maxLabels: 2, want: shortSigningDomain},
		{name: "exact narrow labels", value: shortSigningDomain, maxBytes: 253, maxLabels: 2, want: shortSigningDomain},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := CanonicalSigningDomain(test.value, test.maxBytes, test.maxLabels)
			if err != nil || got != test.want {
				t.Fatalf("valid domain case was not canonicalized")
			}
		})
	}
}

// TestCanonicalSigningDomainRejectsInvalidGrammarAndBounds verifies no repair or non-ASCII extension is accepted.
func TestCanonicalSigningDomainRejectsInvalidGrammarAndBounds(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		maxBytes  int
		maxLabels int
	}{
		{name: "empty", maxBytes: 253, maxLabels: 127},
		{name: "terminal dot", value: "example.test.", maxBytes: 253, maxLabels: 127},
		{name: "empty label", value: "a..invalid", maxBytes: 253, maxLabels: 127},
		{name: "leading hyphen", value: "-example.test", maxBytes: 253, maxLabels: 127},
		{name: "trailing hyphen", value: "example-.test", maxBytes: 253, maxLabels: 127},
		{name: "underscore", value: "example_test", maxBytes: 253, maxLabels: 127},
		{name: "wildcard", value: "*.example.test", maxBytes: 253, maxLabels: 127},
		{name: "slash", value: "example/test", maxBytes: 253, maxLabels: 127},
		{name: "space", value: "example .test", maxBytes: 253, maxLabels: 127},
		{name: "nul", value: "example\x00.test", maxBytes: 253, maxLabels: 127},
		{name: "unicode", value: "münich.invalid", maxBytes: 253, maxLabels: 127},
		{name: "label one over", value: strings.Repeat("a", 64) + ".test", maxBytes: 253, maxLabels: 127},
		{name: "narrow bytes one over", value: "aa.test", maxBytes: 6, maxLabels: 2},
		{name: "narrow labels one over", value: "a.b.test", maxBytes: 253, maxLabels: 2},
		{name: "zero byte maximum", value: testSigningDomain, maxLabels: 127},
		{name: "negative byte maximum", value: testSigningDomain, maxBytes: -1, maxLabels: 127},
		{name: "wide byte maximum", value: testSigningDomain, maxBytes: 254, maxLabels: 127},
		{name: "zero label maximum", value: testSigningDomain, maxBytes: 253},
		{name: "negative label maximum", value: testSigningDomain, maxBytes: 253, maxLabels: -1},
		{name: "wide label maximum", value: testSigningDomain, maxBytes: 253, maxLabels: 128},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := CanonicalSigningDomain(test.value, test.maxBytes, test.maxLabels)
			if err == nil || got != "" || !IsErrorClass(err, ErrorClassContract) {
				t.Fatalf("invalid domain case was not rejected")
			}
			if strings.Contains(err.Error(), test.value) && test.value != "" {
				t.Fatal("domain input leaked through the error")
			}
		})
	}
}

// TestNewQueryDelegatesDomainCanonicalizationAndKeepsOwnerLimitSeparate verifies the shared seam does not absorb owner policy.
func TestNewQueryDelegatesDomainCanonicalizationAndKeepsOwnerLimitSeparate(t *testing.T) {
	query, err := NewQuery("EXAMPLE.TEST", "Selector", AlgorithmEd25519SHA256, DefaultLimits())
	if err != nil || query.SigningDomain() != testSigningDomain || query.Selector() != testSelector {
		t.Fatalf("NewQuery() domain=%q selector=%q error=%v", query.SigningDomain(), query.Selector(), err)
	}

	exactDomain := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 61),
	}, ".")
	if canonical, canonicalErr := CanonicalSigningDomain(exactDomain, 253, 127); canonicalErr != nil || canonical != exactDomain {
		t.Fatalf("CanonicalSigningDomain(exact) = %q, %v", canonical, canonicalErr)
	}
	if _, queryErr := NewQuery(exactDomain, "s", AlgorithmRSASHA256, HardLimits()); !IsErrorClass(queryErr, ErrorClassPermanent) {
		t.Fatalf("NewQuery(exact domain with combined owner overflow) error = %v, want permanent", queryErr)
	}
}

// TestCanonicalSelectorValidatesIndependentExactBounds verifies selector grammar before owner construction.
func TestCanonicalSelectorValidatesIndependentExactBounds(t *testing.T) {
	exactBytes := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 61),
	}, ".")
	exactLabels := strings.Repeat("a.", 126) + "a"
	for name, input := range map[string]string{
		"uppercase":    "Selector.EXAMPLE",
		"exact bytes":  exactBytes,
		"exact labels": exactLabels,
	} {
		got, err := CanonicalSelector(input, 253, 127)
		if err != nil || got != strings.ToLower(input) {
			t.Fatalf("%s selector rejected", name)
		}
	}
	for _, test := range []struct {
		value     string
		maxBytes  int
		maxLabels int
	}{
		{value: "", maxBytes: 253, maxLabels: 127},
		{value: "selector.", maxBytes: 253, maxLabels: 127},
		{value: "selector..test", maxBytes: 253, maxLabels: 127},
		{value: "_selector", maxBytes: 253, maxLabels: 127},
		{value: "sélector", maxBytes: 253, maxLabels: 127},
		{value: strings.Repeat("a", 64), maxBytes: 253, maxLabels: 127},
		{value: "aa", maxBytes: 1, maxLabels: 127},
		{value: "a.b", maxBytes: 253, maxLabels: 1},
		{value: testSelector, maxBytes: 0, maxLabels: 127},
		{value: testSelector, maxBytes: 254, maxLabels: 127},
		{value: testSelector, maxBytes: 253, maxLabels: 0},
		{value: testSelector, maxBytes: 253, maxLabels: 128},
	} {
		if got, err := CanonicalSelector(test.value, test.maxBytes, test.maxLabels); err == nil || got != "" ||
			!IsErrorClass(err, ErrorClassContract) {
			t.Fatal("invalid selector case was not rejected")
		}
	}
}
