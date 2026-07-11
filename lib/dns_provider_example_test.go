package dkim2_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	dkim2 "github.com/croessner/dkim2"
)

//go:embed testdata/vectors/draft-chuang-dkim2-dns-04/dns-golden.json
var dnsExampleManifestJSON []byte

type dnsExampleManifest struct {
	RSATestingStrictTXT string `json:"rsa_testing_strict_txt"`
}

type dnsExampleTransport struct {
	lookup dkim2.TXTLookupResult
	calls  int
}

// LookupTXT returns one synthetic already-concatenated RR without exposing the sensitive owner.
func (t *dnsExampleTransport) LookupTXT(ctx context.Context, _ string) (dkim2.TXTLookupResult, error) {
	if err := ctx.Err(); err != nil {
		return dkim2.TXTLookupResult{}, err
	}
	t.calls++
	return t.lookup, nil
}

// ExampleNewDNSPublicKeyProvider demonstrates injected DNS verification and bounded metadata.
func ExampleNewDNSPublicKeyProvider() {
	transport, err := newDNSExampleTransport()
	if err != nil {
		fmt.Println("fixture error")
		return
	}
	config := dkim2.DefaultDNSProviderConfig()
	config.Clock = func() time.Time { return time.Unix(1700000000, 0) }
	provider, err := dkim2.NewDNSPublicKeyProviderWithConfig(transport, config)
	if err != nil {
		fmt.Println("provider error")
		return
	}
	verifier, err := dkim2.NewVerifier(provider, dkim2.WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		fmt.Println("verifier error")
		return
	}
	result, err := verifier.Verify(context.Background(), syntheticExampleRequest())
	if err != nil {
		fmt.Println("caller or API error")
		return
	}
	fact := result.SignatureSets()[0]
	metadata := fact.KeyPolicyMetadata()
	fmt.Println(result.State(), result.PrimaryReason())
	fmt.Println(fact.Algorithm(), fact.Status(), fact.Reason())
	fmt.Println(metadata.TestingDeclared(), metadata.StrictIdentityDeclared(), metadata.StrictIdentityApplicable())
	fmt.Println("lookups", transport.calls)

	// Output:
	// PASS none
	// rsa-sha256 pass none
	// true true false
	// lookups 1
}

// ExampleDNSProviderConfig demonstrates TTL-backed caching and caller cancellation.
func ExampleDNSProviderConfig() {
	transport, err := newDNSExampleTransport()
	if err != nil {
		fmt.Println("fixture error")
		return
	}
	config := dkim2.DefaultDNSProviderConfig()
	config.Clock = func() time.Time { return time.Unix(1700000000, 0) }
	config.Limits.MaxCacheEntries = 4
	config.Limits.MaxPositiveTTL = 30 * time.Second
	config.Limits.LookupTimeout = 2 * time.Second
	provider, err := dkim2.NewDNSPublicKeyProviderWithConfig(transport, config)
	if err != nil {
		fmt.Println("provider error")
		return
	}
	verifier, err := dkim2.NewVerifier(provider, dkim2.WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		fmt.Println("verifier error")
		return
	}
	first, firstErr := verifier.Verify(context.Background(), syntheticExampleRequest())
	second, secondErr := verifier.Verify(context.Background(), syntheticExampleRequest())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled, canceledErr := verifier.Verify(ctx, syntheticExampleRequest())
	fmt.Println(first.State(), second.State(), firstErr == nil && secondErr == nil, "lookups", transport.calls)
	fmt.Println(errors.Is(canceledErr, context.Canceled), canceled.State() == "", "lookups", transport.calls)
	fmt.Println(config.Limits.MaxCacheEntries, config.Limits.MaxPositiveTTL, config.Limits.LookupTimeout)

	// Output:
	// PASS PASS true lookups 1
	// true true lookups 1
	// 4 30s 2s
}

// newDNSExampleTransport constructs a frozen public-only DNS transport fixture.
func newDNSExampleTransport() (*dnsExampleTransport, error) {
	var manifest dnsExampleManifest
	if err := json.Unmarshal(dnsExampleManifestJSON, &manifest); err != nil {
		return nil, err
	}
	lookup, err := dkim2.NewFoundTXTLookupResult([][]byte{[]byte(manifest.RSATestingStrictTXT)}, time.Minute, dkim2.DNSSECStatusUnavailable)
	if err != nil {
		return nil, err
	}
	return &dnsExampleTransport{lookup: lookup}, nil
}
