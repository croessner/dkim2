package dkim2

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/routeplan"
	"github.com/croessner/dkim2/internal/verify"
)

const testDomainPolicyOwner = "_domainkey.example.test."

// domainPolicyProviderFunc adapts a function to DomainPolicyProvider.
type domainPolicyProviderFunc func(context.Context, DomainPolicyQuery) (DomainPolicyStatus, error)

// LookupDomainPolicy invokes the test function.
func (f domainPolicyProviderFunc) LookupDomainPolicy(ctx context.Context, query DomainPolicyQuery) (DomainPolicyStatus, error) {
	return f(ctx, query)
}

// TestDNSPublicKeyProviderResolvesDomainPolicyRecords pins the Draft-09
// Section 3.8 record selection through the public DNS provider: records not
// beginning with v=DKIM1 are ignored, flags are case-sensitive and split on
// ':', more than one remaining record is ambiguous, an invalid tag-list is
// invalid, absence authorizes, and a temporary DNS failure stays temporary.
func TestDNSPublicKeyProviderResolvesDomainPolicyRecords(t *testing.T) {
	twoRecords, err := NewFoundTXTLookupResult([][]byte{[]byte("v=DKIM1"), []byte("v=DKIM1; f=strict")}, time.Minute, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		lookup TXTLookupResult
		err    error
		status DomainPolicyStatus
		class  ProviderErrorClass
	}{
		{name: "nxdomain or nodata authorizes", lookup: mustPublicAbsentLookup(t), status: DomainPolicyAuthorized},
		{name: "no f tag", lookup: mustPublicFoundLookup(t, []byte("v=DKIM1")), status: DomainPolicyAuthorized},
		{name: "strict flag", lookup: mustPublicFoundLookup(t, []byte("v=DKIM1; f=strict")), status: DomainPolicyStrict},
		{name: "flags are case-sensitive", lookup: mustPublicFoundLookup(t, []byte("v=DKIM1; f=Strict")), status: DomainPolicyAuthorized},
		{name: "unknown flags ignored", lookup: mustPublicFoundLookup(t, []byte("v=DKIM1; f=foo:strict")), status: DomainPolicyStrict},
		{name: "p tag irrelevant", lookup: mustPublicFoundLookup(t, []byte("v=DKIM1; p=; f=strict")), status: DomainPolicyStrict},
		{name: "record without v ignored", lookup: mustPublicFoundLookup(t, []byte("f=strict")), status: DomainPolicyAuthorized},
		{name: "foreign version ignored", lookup: mustPublicFoundLookup(t, []byte("v=DKIM2; f=strict")), status: DomainPolicyAuthorized},
		{name: "two records ambiguous", lookup: twoRecords, status: DomainPolicyAmbiguous},
		{name: "invalid tag-list", lookup: mustPublicFoundLookup(t, []byte("v=DKIM1; f")), status: DomainPolicyInvalid},
		{name: "temporary DNS failure", err: NewTemporaryProviderError(), class: ProviderErrorClassTemporary},
		{name: "permanent DNS failure", err: NewPermanentProviderError(), status: DomainPolicyInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			provider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(_ context.Context, owner string) (TXTLookupResult, error) {
				calls++
				if owner != testDomainPolicyOwner {
					t.Fatalf("owner = %q", owner)
				}
				return tt.lookup, tt.err
			}))
			if err != nil {
				t.Fatal(err)
			}
			query, err := NewDomainPolicyQuery("example.test")
			if err != nil {
				t.Fatal(err)
			}
			status, err := provider.LookupDomainPolicy(context.Background(), query)
			if calls != 1 || status != tt.status || ProviderErrorClassOf(err) != tt.class || (tt.class == "") != (err == nil) {
				t.Fatalf("LookupDomainPolicy() = %q, %v (class %q) calls=%d", status, err, ProviderErrorClassOf(err), calls)
			}
		})
	}
}

// TestNetTXTTransportAcceptsDomainPolicyOwner reproduces the F5 seam: the
// standard-library transport must accept the policy owner kind, or every
// upward candidate would turn into a provider contract failure.
func TestNetTXTTransportAcceptsDomainPolicyOwner(t *testing.T) {
	resolver := &fakeNetTXTResolver{records: []string{"v=DKIM1; f=strict"}}
	transport, err := newNetTXTTransport(resolver)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewDNSPublicKeyProvider(transport)
	if err != nil {
		t.Fatal(err)
	}
	query, err := NewDomainPolicyQuery("example.test")
	if err != nil {
		t.Fatal(err)
	}
	if status, err := provider.LookupDomainPolicy(context.Background(), query); err != nil || status != DomainPolicyStrict || resolver.calls != 1 {
		t.Fatalf("LookupDomainPolicy() = %q, %v calls=%d", status, err, resolver.calls)
	}
	for _, owner := range []string{"_domainkey.", "x._domainkey._domainkey.example.test.", "_domainkey.Example.test."} {
		if _, err := transport.LookupTXT(context.Background(), owner); err == nil {
			t.Fatalf("LookupTXT(%q) accepted a malformed owner", owner)
		}
	}
}

// TestNewDomainPolicyQueryRequiresCanonicalALabel verifies that only an
// exact canonical A-label domain forms a query.
func TestNewDomainPolicyQueryRequiresCanonicalALabel(t *testing.T) {
	if query, err := NewDomainPolicyQuery("xn--bcher-kva.example"); err != nil || query.Domain() != "xn--bcher-kva.example" {
		t.Fatalf("NewDomainPolicyQuery(A-label) = %q, %v", query.Domain(), err)
	}
	for _, domain := range []string{"", "Example.test", "bücher.example", "a..test", "example.test."} {
		if _, err := NewDomainPolicyQuery(domain); err == nil {
			t.Fatalf("NewDomainPolicyQuery(%q) accepted", domain)
		}
	}
	query, _ := NewDomainPolicyQuery("example.test")
	if query.String() != domainPolicyQueryRedactedText {
		t.Fatal("query formatting exposed the domain")
	}
}

// TestNewVerifierRequiresSubdomainFromChoice pins D9: the public verifier
// requires an explicit Section 11.1 choice; a key provider that is also a
// DomainPolicyProvider (the DNS provider) is a choice by itself.
func TestNewVerifierRequiresSubdomainFromChoice(t *testing.T) {
	keys := publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return PublicKeyResult{}, NewTemporaryProviderError()
	})
	policy := domainPolicyProviderFunc(func(context.Context, DomainPolicyQuery) (DomainPolicyStatus, error) {
		return DomainPolicyAuthorized, nil
	})
	dnsProvider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) {
		return TXTLookupResult{}, NewTemporaryProviderError()
	}))
	if err != nil {
		t.Fatal(err)
	}
	var typedNil domainPolicyProviderFunc
	rejected := [][]VerifierOption{
		nil,
		{WithDomainPolicyProvider(nil)},
		{WithDomainPolicyProvider(typedNil)},
		{WithDomainPolicyProvider(policy), WithoutSubdomainFromAuthorization()},
		{WithoutSubdomainFromAuthorization(), WithDomainPolicyProvider(policy)},
	}
	for index, options := range rejected {
		var apiErr *APIError
		if _, err := NewVerifier(keys, options...); !errors.As(err, &apiErr) || apiErr.Code() != APIErrorCodeInvalidOption {
			t.Fatalf("case %d: NewVerifier() error = %v, want invalid_option", index, err)
		}
	}
	for index, options := range [][]VerifierOption{{WithoutSubdomainFromAuthorization()}, {WithDomainPolicyProvider(policy)}} {
		if verifier, err := NewVerifier(keys, options...); err != nil || verifier == nil {
			t.Fatalf("case %d: NewVerifier() = %v, %v", index, verifier, err)
		}
	}
	if verifier, err := NewVerifier(dnsProvider); err != nil || verifier == nil {
		t.Fatalf("NewVerifier(DNS provider) = %v, %v", verifier, err)
	}
}

// TestNewSignerRequiresSubdomainFromChoice pins D9 for the signer facade,
// whose VerifyForRevision path builds a verifier.
func TestNewSignerRequiresSubdomainFromChoice(t *testing.T) {
	provider := &publicSigningProvider{rsaKey: loadPublicSigningRSAKey(t)}
	routes := publicRouteMemoryAuthority{value: routeplan.NewMemoryAuthority(), calls: &atomic.Int64{}}
	policy := domainPolicyProviderFunc(func(context.Context, DomainPolicyQuery) (DomainPolicyStatus, error) {
		return DomainPolicyAuthorized, nil
	})
	if _, err := NewSigner(provider, routes, &authorizeOrdinary{}, provider); err == nil {
		t.Fatal("NewSigner() accepted a missing Section 11.1 choice")
	}
	if _, err := NewSigner(provider, routes, &authorizeOrdinary{}, provider,
		WithSignerDomainPolicyProvider(policy), WithoutSignerSubdomainFromAuthorization()); err == nil {
		t.Fatal("NewSigner() accepted a conflicting Section 11.1 choice")
	}
	for _, option := range []SignerOption{WithSignerDomainPolicyProvider(policy), WithoutSignerSubdomainFromAuthorization()} {
		if signer, err := NewSigner(provider, routes, &authorizeOrdinary{}, provider, option); err != nil || signer == nil {
			t.Fatalf("NewSigner() = %v, %v", signer, err)
		}
	}
}

// TestDomainPolicyBridgeMapsProviderContract verifies that the bridge keeps
// temporary failures retryable, preserves the live caller context error, and
// fails every other pair closed without retaining causes.
func TestDomainPolicyBridgeMapsProviderContract(t *testing.T) {
	tests := []struct {
		name   string
		status DomainPolicyStatus
		err    error
		want   verify.DomainPolicyStatus
		class  verify.ProviderFailureClass
	}{
		{name: "authorized", status: DomainPolicyAuthorized, want: verify.DomainPolicyAuthorized},
		{name: "strict status", status: DomainPolicyStrict, want: verify.DomainPolicyStrict},
		{name: "ambiguous", status: DomainPolicyAmbiguous, want: verify.DomainPolicyAmbiguous},
		{name: "invalid", status: DomainPolicyInvalid, want: verify.DomainPolicyInvalid},
		{name: "unknown status", status: DomainPolicyStatus("future"), want: verify.DomainPolicyInvalid},
		{name: "temporary failure", err: NewTemporaryProviderError(), class: verify.ProviderFailureTemporary},
		{name: "permanent failure", err: NewPermanentProviderError(), class: verify.ProviderFailurePermanent},
		{name: "unclassified", err: errors.New("raw cause"), class: verify.ProviderFailurePermanent},
		{name: "status with error", status: DomainPolicyStrict, err: NewTemporaryProviderError(), class: verify.ProviderFailureContract},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bridge := domainPolicyBridge{provider: domainPolicyProviderFunc(func(_ context.Context, query DomainPolicyQuery) (DomainPolicyStatus, error) {
				if query.Domain() != "example.test" {
					t.Fatalf("query domain = %q", query.Domain())
				}
				return tt.status, tt.err
			})}
			status, err := bridge.LookupDomainPolicy(context.Background(), "example.test")
			if status != tt.want || verify.ProviderFailureClassOf(err) != tt.class {
				t.Fatalf("LookupDomainPolicy() = %q, %v", status, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bridge := domainPolicyBridge{provider: domainPolicyProviderFunc(func(ctx context.Context, _ DomainPolicyQuery) (DomainPolicyStatus, error) {
		return "", ctx.Err()
	})}
	if _, err := bridge.LookupDomainPolicy(ctx, "example.test"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled LookupDomainPolicy() error = %v", err)
	}
}
