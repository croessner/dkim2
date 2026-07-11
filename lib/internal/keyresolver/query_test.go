package keyresolver

import (
	"strings"
	"testing"
)

const (
	testSigningDomain = "example.test"
	testSelector      = "selector"
)

// TestNewQueryBuildsCanonicalAbsoluteOwners verifies simple and dotted selector ownership.
func TestNewQueryBuildsCanonicalAbsoluteOwners(t *testing.T) {
	tests := []struct {
		name         string
		domain       string
		selector     string
		algorithm    Algorithm
		presentation string
		absolute     string
	}{
		{name: "simple", domain: "Example.COM", selector: "SELector", algorithm: AlgorithmRSASHA256, presentation: "selector._domainkey.example.com", absolute: "selector._domainkey.example.com."},
		{name: "dotted", domain: "Mail.Example", selector: "march2005.Reykjavik", algorithm: AlgorithmEd25519SHA256, presentation: "march2005.reykjavik._domainkey.mail.example", absolute: "march2005.reykjavik._domainkey.mail.example."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := NewQuery(tt.domain, tt.selector, tt.algorithm, DefaultLimits())
			if err != nil {
				t.Fatalf("NewQuery() error = %v", err)
			}
			if query.SigningDomain() != strings.ToLower(tt.domain) || query.Selector() != strings.ToLower(tt.selector) || query.Algorithm() != tt.algorithm || query.PresentationOwner() != tt.presentation || query.AbsoluteOwner() != tt.absolute {
				t.Fatalf("NewQuery() = %#v", query)
			}
		})
	}
}

// TestNewQueryRejectsInvalidBoundaryState verifies invalid components fail as contract state.
func TestNewQueryRejectsInvalidBoundaryState(t *testing.T) {
	tests := []struct {
		name, domain, selector string
		algorithm              Algorithm
	}{
		{name: "empty domain", selector: "s", algorithm: AlgorithmRSASHA256},
		{name: "empty selector", domain: testSigningDomain, algorithm: AlgorithmRSASHA256},
		{name: "zero algorithm", domain: testSigningDomain, selector: "s"},
		{name: "unknown algorithm", domain: testSigningDomain, selector: "s", algorithm: Algorithm("future")},
		{name: "empty label", domain: "example..test", selector: "s", algorithm: AlgorithmRSASHA256},
		{name: "selector empty label", domain: testSigningDomain, selector: "a..b", algorithm: AlgorithmRSASHA256},
		{name: "leading hyphen", domain: "-example.test", selector: "s", algorithm: AlgorithmRSASHA256},
		{name: "trailing hyphen", domain: "example-.test", selector: "s", algorithm: AlgorithmRSASHA256},
		{name: "selector leading hyphen", domain: testSigningDomain, selector: "-selector", algorithm: AlgorithmRSASHA256},
		{name: "selector trailing hyphen", domain: testSigningDomain, selector: "selector-", algorithm: AlgorithmRSASHA256},
		{name: "underscore", domain: "example_test", selector: "s", algorithm: AlgorithmRSASHA256},
		{name: "selector underscore", domain: testSigningDomain, selector: "select_or", algorithm: AlgorithmRSASHA256},
		{name: "space", domain: testSigningDomain, selector: "bad value", algorithm: AlgorithmRSASHA256},
		{name: "slash", domain: "example/test", selector: "s", algorithm: AlgorithmRSASHA256},
		{name: "nul", domain: testSigningDomain + "\x00", selector: "s", algorithm: AlgorithmRSASHA256},
		{name: "non ascii", domain: "exämple.test", selector: "s", algorithm: AlgorithmRSASHA256},
		{name: "selector non ascii", domain: testSigningDomain, selector: "sélector", algorithm: AlgorithmRSASHA256},
		{name: "terminal dot", domain: testSigningDomain + ".", selector: "s", algorithm: AlgorithmRSASHA256},
		{name: "selector terminal dot", domain: testSigningDomain, selector: "selector.", algorithm: AlgorithmRSASHA256},
		{name: "long label", domain: strings.Repeat("a", 64) + ".test", selector: "s", algorithm: AlgorithmRSASHA256},
		{name: "long selector label", domain: testSigningDomain, selector: strings.Repeat("a", 64), algorithm: AlgorithmRSASHA256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewQuery(tt.domain, tt.selector, tt.algorithm, DefaultLimits())
			if err == nil || !IsErrorClass(err, ErrorClassContract) {
				t.Fatalf("NewQuery() error = %v, want contract", err)
			}
			if len(tt.domain) > 7 && strings.Contains(err.Error(), tt.domain) || len(tt.selector) > 7 && strings.Contains(err.Error(), tt.selector) {
				t.Fatal("query error exposed input")
			}
		})
	}
}

// TestNewQueryClassifiesCombinedOwnerOverflowAsPermanent verifies valid components can exceed owner length.
func TestNewQueryClassifiesCombinedOwnerOverflowAsPermanent(t *testing.T) {
	selector := strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63)}, ".")
	exactDomain := strings.Join([]string{strings.Repeat("c", 63), strings.Repeat("d", 50)}, ".")
	query, err := NewQuery(exactDomain, selector, AlgorithmRSASHA256, HardLimits())
	if err != nil || len(query.PresentationOwner()) != 253 {
		t.Fatalf("exact owner NewQuery() len=%d error=%v", len(query.PresentationOwner()), err)
	}
	overDomain := strings.Join([]string{strings.Repeat("c", 63), strings.Repeat("d", 51)}, ".")
	_, err = NewQuery(overDomain, selector, AlgorithmRSASHA256, HardLimits())
	if err == nil || !IsErrorClass(err, ErrorClassPermanent) {
		t.Fatalf("NewQuery() error = %v, want permanent", err)
	}
	if strings.Contains(err.Error(), overDomain) || strings.Contains(err.Error(), selector) {
		t.Fatal("permanent owner overflow error exposed query input")
	}
}

// TestNewQueryHonorsNarrowAggregateAndLabelLimits verifies every query limit is enforced.
func TestNewQueryHonorsNarrowAggregateAndLabelLimits(t *testing.T) {
	tests := []func(*Limits){
		func(l *Limits) { l.MaxSelectorBytes = 2 },
		func(l *Limits) { l.MaxSelectorLabels = 1 },
		func(l *Limits) { l.MaxSigningDomainBytes = 3 },
		func(l *Limits) { l.MaxSigningDomainLabels = 1 },
		func(l *Limits) { l.MaxOwnerBytes = 10 },
	}
	for index, mutate := range tests {
		limits := DefaultLimits()
		mutate(&limits)
		_, err := NewQuery(testSigningDomain, "a.b", AlgorithmRSASHA256, limits)
		if err == nil {
			t.Fatalf("case %d unexpectedly passed", index)
		}
	}
}

// TestNewQueryHonorsExactLabelCount verifies shared domain and selector label-count boundaries.
func TestNewQueryHonorsExactLabelCount(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxSelectorLabels = 2
	limits.MaxSigningDomainLabels = 2
	if _, err := NewQuery(testSigningDomain, "a.b", AlgorithmRSASHA256, limits); err != nil {
		t.Fatalf("exact label counts rejected: %v", err)
	}
	for _, query := range []struct{ domain, selector string }{{testSigningDomain, "a.b.c"}, {"a.example.test", "a.b"}} {
		if _, err := NewQuery(query.domain, query.selector, AlgorithmRSASHA256, limits); err == nil {
			t.Fatalf("over label count accepted: %#v", query)
		}
	}
}

// TestValidAbsoluteOwnerUsesCanonicalQueryGrammar verifies transport owners share query validation.
func TestValidAbsoluteOwnerUsesCanonicalQueryGrammar(t *testing.T) {
	valid := []string{"s._domainkey.example.test.", "a.b._domainkey.example.test."}
	for _, owner := range valid {
		if !ValidAbsoluteOwner(owner) {
			t.Fatalf("ValidAbsoluteOwner(%q) = false", owner)
		}
	}
	invalid := []string{"", "relative.example", ".", "Bad._domainkey.example.test.", "s._domainkey.example..test.", "s._domainkey.exämple.test.", "s._domainkey.example.test..", "s.example.test.", "_domainkey.example.test."}
	for _, owner := range invalid {
		if ValidAbsoluteOwner(owner) {
			t.Fatalf("ValidAbsoluteOwner(%q) = true", owner)
		}
	}
}
