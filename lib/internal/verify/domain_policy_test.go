package verify

import (
	"context"
	"errors"
	"testing"
)

// scriptedDomainPolicyProvider answers each domain from a fixed table and
// records the lookup order.
type scriptedDomainPolicyProvider struct {
	answers map[string]scriptedDomainPolicyAnswer
	calls   []string
	cancel  context.CancelFunc
}

// scriptedDomainPolicyAnswer is one provider result pair.
type scriptedDomainPolicyAnswer struct {
	status DomainPolicyStatus
	err    error
}

// LookupDomainPolicy returns the scripted answer and cancels the caller
// context after the first lookup when a cancel function is configured.
func (p *scriptedDomainPolicyProvider) LookupDomainPolicy(_ context.Context, domain string) (DomainPolicyStatus, error) {
	p.calls = append(p.calls, domain)
	if p.cancel != nil {
		p.cancel()
	}
	answer := p.answers[domain]
	return answer.status, answer.err
}

// TestResolveUpwardFromCandidatesCombinesSeveralRecords proves the Section
// 14.6 sig-all precedence across several upward From domains: strict wins
// over every error, the first ambiguous or invalid record in field order wins
// over temporary, and every candidate is resolved so usage stays exact.
func TestResolveUpwardFromCandidatesCombinesSeveralRecords(t *testing.T) {
	temporary := scriptedDomainPolicyAnswer{err: NewProviderFailure(ProviderFailureTemporary)}
	authorized := scriptedDomainPolicyAnswer{status: DomainPolicyAuthorized}
	strict := scriptedDomainPolicyAnswer{status: DomainPolicyStrict}
	ambiguous := scriptedDomainPolicyAnswer{status: DomainPolicyAmbiguous}
	invalid := scriptedDomainPolicyAnswer{status: DomainPolicyInvalid}
	tests := []struct {
		name    string
		answers []scriptedDomainPolicyAnswer
		want    RevisionProofOutcome
	}{
		{name: "all authorized", answers: []scriptedDomainPolicyAnswer{authorized, authorized, authorized}, want: ""},
		{name: "strict after errors", answers: []scriptedDomainPolicyAnswer{temporary, ambiguous, strict}, want: RevisionProofFromSubdomainForbidden},
		{name: "first permanent in field order", answers: []scriptedDomainPolicyAnswer{temporary, invalid, ambiguous}, want: RevisionProofDomainPolicyInvalid},
		{name: "ambiguous before invalid", answers: []scriptedDomainPolicyAnswer{ambiguous, authorized, invalid}, want: RevisionProofDomainPolicyAmbiguous},
		{name: "temporary only", answers: []scriptedDomainPolicyAnswer{authorized, temporary, authorized}, want: RevisionProofDomainPolicyTemporary},
	}
	domains := []string{"a.example.test", "b.example.test", "c.example.test"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &scriptedDomainPolicyProvider{answers: map[string]scriptedDomainPolicyAnswer{}}
			for index, domain := range domains {
				provider.answers[domain] = tt.answers[index]
			}
			outcome, err := SubdomainFromAuthorization(provider).resolveUpwardFromCandidates(context.Background(), domains)
			if err != nil || outcome != tt.want {
				t.Fatalf("resolveUpwardFromCandidates() = %q, %v; want %q", outcome, err, tt.want)
			}
			if len(provider.calls) != len(domains) {
				t.Fatalf("lookups = %v, want every candidate in field order", provider.calls)
			}
		})
	}
}

// TestResolveUpwardFromCandidatesStopsWhenTheCallerContextEnds proves that a
// cancelled caller context is returned unchanged and never becomes a protocol
// outcome, and that no further candidate is resolved.
func TestResolveUpwardFromCandidatesStopsWhenTheCallerContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider := &scriptedDomainPolicyProvider{answers: map[string]scriptedDomainPolicyAnswer{}, cancel: cancel}
	outcome, err := SubdomainFromAuthorization(provider).resolveUpwardFromCandidates(ctx, []string{"a.example.test", "b.example.test"})
	if !errors.Is(err, context.Canceled) || outcome != "" || len(provider.calls) != 1 {
		t.Fatalf("resolveUpwardFromCandidates() = %q, %v after %d lookups; want context.Canceled after 1", outcome, err, len(provider.calls))
	}
}
