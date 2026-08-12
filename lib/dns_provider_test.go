package dkim2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

// TestDNSPublicKeyProviderMapsResolverOutcomes verifies exact declared public result states.
func TestDNSPublicKeyProviderMapsResolverOutcomes(t *testing.T) {
	edKey := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	tests := []struct {
		name      string
		lookup    TXTLookupResult
		algorithm Algorithm
		status    PublicKeyStatus
		metadata  bool
	}{
		{name: "missing", lookup: mustPublicAbsentLookup(t), algorithm: AlgorithmRSASHA256, status: PublicKeyStatusMissing},
		{name: testNameAmbiguous, lookup: mustPublicAmbiguousLookup(t), algorithm: AlgorithmRSASHA256, status: PublicKeyStatusAmbiguous},
		{name: testNameInvalid, lookup: mustPublicFoundLookup(t, []byte("v=DKIM1; p=%%%")), algorithm: AlgorithmRSASHA256, status: PublicKeyStatusInvalid},
		{name: testNameRevoked, lookup: mustPublicFoundLookup(t, []byte("v=DKIM1; p=; t=y:s")), algorithm: AlgorithmRSASHA256, status: PublicKeyStatusRevoked, metadata: true},
		{name: testNameUnsupported, lookup: mustPublicFoundLookup(t, []byte("v=DKIM1; k=future; p=QQ==; t=y:s")), algorithm: AlgorithmRSASHA256, status: PublicKeyStatusUnsupportedKeyType, metadata: true},
		{name: testNameMismatch, lookup: mustPublicFoundLookup(t, []byte("v=DKIM1; k=ed25519; p="+edKey+"; t=y:s")), algorithm: AlgorithmRSASHA256, status: PublicKeyStatusAlgorithmMismatch, metadata: true},
		{name: "found", lookup: mustPublicFoundLookup(t, []byte("v=DKIM1; k=ed25519; p="+edKey+"; t=y:s")), algorithm: AlgorithmEd25519SHA256, status: PublicKeyStatusFound, metadata: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			provider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(_ context.Context, owner string) (TXTLookupResult, error) {
				calls++
				if owner != "selector._domainkey.example.test." {
					t.Fatalf("owner = %q", owner)
				}
				return tt.lookup, nil
			}))
			if err != nil {
				t.Fatalf("NewDNSPublicKeyProvider() error = %v", err)
			}
			result, err := provider.LookupPublicKey(context.Background(), newPublicKeyQuery("example.test", "selector", tt.algorithm))
			metadata := result.KeyPolicyMetadata()
			if err != nil || calls != 1 || result.Status() != tt.status || metadata.TestingDeclared() != tt.metadata {
				t.Fatalf("LookupPublicKey() = %q metadata=%#v calls=%d error=%v", result.Status(), metadata, calls, err)
			}
			if tt.metadata && (!metadata.StrictIdentityDeclared() || metadata.StrictIdentityApplicable()) {
				t.Fatalf("strict metadata = %#v", metadata)
			}
		})
	}
}

// TestDNSPublicKeyProviderMapsDisjointErrors verifies caller and provider error pairs.
func TestDNSPublicKeyProviderMapsDisjointErrors(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		class ProviderErrorClass
	}{
		{name: "temporary", err: NewTemporaryProviderError(), class: ProviderErrorClassTemporary},
		{name: "permanent", err: NewPermanentProviderError(), class: ProviderErrorClassPermanent},
		{name: "unclassified provider error", err: errors.New("SECRET-MARKER.example")},
		{name: "unclassified deadline", err: context.DeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) { return TXTLookupResult{}, tt.err }))
			if err != nil {
				t.Fatal(err)
			}
			result, lookupErr := provider.LookupPublicKey(context.Background(), newPublicKeyQuery("example.test", "selector", AlgorithmRSASHA256))
			if !result.IsZero() || lookupErr == nil || ProviderErrorClassOf(lookupErr) != tt.class || lookupErr.Error() == "SECRET-MARKER.example" {
				t.Fatalf("LookupPublicKey() = zero=%v class=%q error=%v", result.IsZero(), ProviderErrorClassOf(lookupErr), lookupErr)
			}
		})
	}
	nonzero := mustPublicAbsentLookup(t)
	provider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) {
		return nonzero, NewTemporaryProviderError()
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, lookupErr := provider.LookupPublicKey(context.Background(), newPublicKeyQuery("example.test", "selector", AlgorithmRSASHA256))
	if !result.IsZero() || lookupErr == nil || ProviderErrorClassOf(lookupErr) != "" {
		t.Fatalf("nonzero plus error = zero=%v error=%v", result.IsZero(), lookupErr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	provider, err = NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) {
		cancel()
		return TXTLookupResult{}, ctx.Err()
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, lookupErr = provider.LookupPublicKey(ctx, newPublicKeyQuery("example.test", "selector", AlgorithmRSASHA256))
	if !result.IsZero() || !errors.Is(lookupErr, context.Canceled) {
		t.Fatalf("caller LookupPublicKey() = zero=%v error=%v", result.IsZero(), lookupErr)
	}
}

// TestDNSPublicKeyProviderRejectsNilAndInvalidQueries verifies constructor and pre-transport contracts.
func TestDNSPublicKeyProviderRejectsNilAndInvalidQueries(t *testing.T) {
	var typedNil txtTransportFunc
	for _, transport := range []TXTTransport{nil, typedNil} {
		if _, err := NewDNSPublicKeyProvider(transport); err == nil {
			t.Fatalf("%T transport accepted", transport)
		}
	}
	calls := 0
	provider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) { calls++; return TXTLookupResult{}, nil }))
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []PublicKeyQuery{
		newPublicKeyQuery("bad_domain.test", "selector", AlgorithmRSASHA256),
		newPublicKeyQuery("example.test", "bad_selector", AlgorithmRSASHA256),
		newPublicKeyQuery("example.test", "selector", AlgorithmUnknown),
	} {
		result, lookupErr := provider.LookupPublicKey(context.Background(), query)
		if !result.IsZero() || lookupErr == nil || ProviderErrorClassOf(lookupErr) != "" {
			t.Fatalf("invalid query result/error = zero=%v/%v", result.IsZero(), lookupErr)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid queries made %d transport calls", calls)
	}
	var zero DNSPublicKeyProvider
	result, lookupErr := zero.LookupPublicKey(context.Background(), newPublicKeyQuery("example.test", "selector", AlgorithmRSASHA256))
	if !result.IsZero() || lookupErr == nil || ProviderErrorClassOf(lookupErr) != "" {
		t.Fatalf("zero provider = zero=%v error=%v", result.IsZero(), lookupErr)
	}
}

// TestDNSPublicKeyProviderDefersRSAPolicyToVerifier proves structural lookup and later policy rejection.
func TestDNSPublicKeyProviderDefersRSAPolicyToVerifier(t *testing.T) {
	tests := []struct {
		name     string
		bits     int
		exponent int
	}{
		{name: "exponent three", bits: 1024, exponent: 3},
		{name: "below minimum", bits: 1023, exponent: 65537},
		{name: "above maximum", bits: 8193, exponent: 65537},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected := dnsPolicyBoundaryRSAKey(tt.bits, tt.exponent)
			payload := []byte("v=DKIM1; p=" + base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(expected)))
			provider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) {
				return mustPublicFoundLookup(t, payload), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			result, lookupErr := provider.LookupPublicKey(context.Background(), newPublicKeyQuery("example.test", "selector", AlgorithmRSASHA256))
			key, found := result.RSAPublicKey()
			if lookupErr != nil || result.Status() != PublicKeyStatusFound || !found || key == nil ||
				key.N.BitLen() != tt.bits || key.E != tt.exponent {
				t.Fatalf("LookupPublicKey() = %q key=%#v error=%v, want found %d-bit e=%d", result.Status(), key, lookupErr, tt.bits, tt.exponent)
			}

			verifier, constructErr := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
			if constructErr != nil {
				t.Fatalf("NewVerifier() error = %v", constructErr)
			}
			verified, verifyErr := verifier.Verify(context.Background(), NewVerifyRequest(publicProviderFixture(t), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			signatures := verified.SignatureSets()
			if verifyErr != nil || verified.State() != ResultStatePERMERROR || verified.PrimaryReason() != ReasonInvalidKey ||
				len(signatures) != 1 || signatures[0].Status() != SignatureStatusPERMERROR || signatures[0].Reason() != ReasonInvalidKey {
				t.Fatalf("Verify() = %q/%q signatures=%#v error=%v, want pre-crypto policy rejection", verified.State(), verified.PrimaryReason(), signatures, verifyErr)
			}
		})
	}
}

// TestDNSPublicKeyProviderRejectsMalformedRSADER verifies structural decoding still fails closed.
func TestDNSPublicKeyProviderRejectsMalformedRSADER(t *testing.T) {
	payload := []byte("v=DKIM1; p=" + base64.StdEncoding.EncodeToString([]byte{0x30, 0x01, 0x02}))
	provider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) {
		return mustPublicFoundLookup(t, payload), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, lookupErr := provider.LookupPublicKey(context.Background(), newPublicKeyQuery("example.test", "selector", AlgorithmRSASHA256))
	if key, found := result.RSAPublicKey(); lookupErr != nil || result.Status() != PublicKeyStatusInvalid || found || key != nil {
		t.Fatalf("LookupPublicKey() = %q key=%#v error=%v, want invalid", result.Status(), key, lookupErr)
	}
}

// dnsPolicyBoundaryRSAKey constructs a structurally valid RSA key outside verifier policy.
func dnsPolicyBoundaryRSAKey(bits, exponent int) *rsa.PublicKey {
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	modulus.SetBit(modulus, 0, 1)
	return &rsa.PublicKey{N: modulus, E: exponent}
}

// TestDNSPublicKeyProviderAcceptsDNSCompatibleKeyRepresentations verifies DNS-04 padding and RSA container compatibility.
func TestDNSPublicKeyProviderAcceptsDNSCompatibleKeyRepresentations(t *testing.T) {
	rsaModulus := new(big.Int).Lsh(big.NewInt(1), 1023)
	rsaModulus.SetBit(rsaModulus, 0, 1)
	rsaKey := &rsa.PublicKey{N: rsaModulus, E: 65537}
	rsaPKCS1 := x509.MarshalPKCS1PublicKey(rsaKey)
	rsaSPKI, err := x509.MarshalPKIXPublicKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	edKey := bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize)
	for _, tt := range []struct {
		name      string
		record    string
		algorithm Algorithm
	}{
		{name: "unpadded PKCS#1 RSA", record: "p=" + base64.RawStdEncoding.EncodeToString(rsaPKCS1), algorithm: AlgorithmRSASHA256},
		{name: "unpadded SPKI RSA", record: "p=" + base64.RawStdEncoding.EncodeToString(rsaSPKI), algorithm: AlgorithmRSASHA256},
		{name: "unpadded raw Ed25519", record: "k=ed25519; p=" + base64.RawStdEncoding.EncodeToString(edKey), algorithm: AlgorithmEd25519SHA256},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider, constructErr := NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) {
				return mustPublicFoundLookup(t, []byte(tt.record)), nil
			}))
			if constructErr != nil {
				t.Fatal(constructErr)
			}
			result, lookupErr := provider.LookupPublicKey(context.Background(), newPublicKeyQuery("example.test", "selector", tt.algorithm))
			if lookupErr != nil || result.Status() != PublicKeyStatusFound {
				t.Fatalf("DNS key = %q error=%v", result.Status(), lookupErr)
			}
		})
	}
}

// TestDNSPublicKeyProviderRejectsStructurallyInvalidRSA verifies shared shape validation before caching.
func TestDNSPublicKeyProviderRejectsStructurallyInvalidRSA(t *testing.T) {
	for _, key := range []*rsa.PublicKey{
		{N: big.NewInt(3234), E: 17},
		{N: big.NewInt(3233), E: 2},
		{N: big.NewInt(3233), E: 18},
		{N: big.NewInt(17), E: 17},
	} {
		payload := []byte("p=" + base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(key)))
		provider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) {
			return mustPublicFoundLookup(t, payload), nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		result, lookupErr := provider.LookupPublicKey(context.Background(), newPublicKeyQuery("example.test", "selector", AlgorithmRSASHA256))
		if lookupErr != nil || result.Status() != PublicKeyStatusInvalid {
			t.Fatalf("invalid RSA structure = %q error=%v", result.Status(), lookupErr)
		}
	}
}

// TestDNSPublicKeyProviderRejectsHugeMixedPublicResultWithoutTraversal verifies O(1) shape validation.
func TestDNSPublicKeyProviderRejectsHugeMixedPublicResultWithoutTraversal(t *testing.T) {
	lookup := TXTLookupResult{state: &txtLookupResultState{
		status: TXTLookupStatusFound, recordCount: 1_000_000_000,
		records: []TXTRecord{newTXTRecord([]byte("SECRET-MARKER"))}, dnssec: DNSSECStatusUnavailable,
	}}
	provider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) { return lookup, nil }))
	if err != nil {
		t.Fatal(err)
	}
	result, lookupErr := provider.LookupPublicKey(context.Background(), newPublicKeyQuery("example.test", "selector", AlgorithmRSASHA256))
	if !result.IsZero() || lookupErr == nil || ProviderErrorClassOf(lookupErr) != "" {
		t.Fatalf("LookupPublicKey() = zero=%v error=%v", result.IsZero(), lookupErr)
	}
}

// TestDNSPublicKeyProviderRejectsContradictoryPublicTransportResults verifies closed shape mapping.
func TestDNSPublicKeyProviderRejectsContradictoryPublicTransportResults(t *testing.T) {
	record := newTXTRecord([]byte("v=DKIM1; p=QQ=="))
	tests := []TXTLookupResult{
		{},
		{state: &txtLookupResultState{status: TXTLookupStatusFound, dnssec: DNSSECStatusUnavailable}},
		{state: &txtLookupResultState{status: TXTLookupStatusFound, recordCount: 1, dnssec: DNSSECStatusUnavailable}},
		{state: &txtLookupResultState{status: TXTLookupStatusFound, records: []TXTRecord{record}, recordCount: 1, absence: TXTAbsenceNODATA, dnssec: DNSSECStatusUnavailable}},
		{state: &txtLookupResultState{status: TXTLookupStatusFound, records: []TXTRecord{record}, recordCount: 1, negativeTTL: time.Second, dnssec: DNSSECStatusUnavailable}},
		{state: &txtLookupResultState{status: TXTLookupStatusAbsent, records: []TXTRecord{record}, recordCount: 1, absence: TXTAbsenceNODATA, dnssec: DNSSECStatusUnavailable}},
		{state: &txtLookupResultState{status: TXTLookupStatusAbsent, absence: TXTAbsenceNODATA, positiveTTL: time.Second, dnssec: DNSSECStatusUnavailable}},
		{state: &txtLookupResultState{status: TXTLookupStatusAbsent, absence: TXTAbsenceNODATA, dnssec: DNSSECStatus("future")}},
	}
	for index, lookup := range tests {
		provider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) { return lookup, nil }))
		if err != nil {
			t.Fatal(err)
		}
		result, lookupErr := provider.LookupPublicKey(context.Background(), newPublicKeyQuery("example.test", "selector", AlgorithmRSASHA256))
		if !result.IsZero() || lookupErr == nil || ProviderErrorClassOf(lookupErr) != "" {
			t.Fatalf("case %d = zero=%v error=%v", index, result.IsZero(), lookupErr)
		}
	}
}

// TestDNSPublicKeyProviderConfigurationControlsCacheAndClock verifies public bounded construction.
func TestDNSPublicKeyProviderConfigurationControlsCacheAndClock(t *testing.T) {
	lookup := mustPublicAbsentLookup(t)
	var calls atomic.Int32
	transport := txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) {
		calls.Add(1)
		return lookup, nil
	})
	config := DefaultDNSProviderConfig()
	now := time.Unix(100, 0)
	config.Clock = func() time.Time { return now }
	provider, err := NewDNSPublicKeyProviderWithConfig(transport, config)
	if err != nil {
		t.Fatal(err)
	}
	query := newPublicKeyQuery("example.test", "selector", AlgorithmRSASHA256)
	for range 2 {
		if _, lookupErr := provider.LookupPublicKey(context.Background(), query); lookupErr != nil {
			t.Fatal(lookupErr)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("configured cache calls = %d", calls.Load())
	}
	now = now.Add(config.Limits.MaxNegativeTTL)
	if _, lookupErr := provider.LookupPublicKey(context.Background(), query); lookupErr != nil {
		t.Fatal(lookupErr)
	}
	if calls.Load() != 2 {
		t.Fatalf("configured exact expiry calls = %d", calls.Load())
	}

	calls.Store(0)
	config = DefaultDNSProviderConfig()
	config.Limits.MaxCacheEntries = 0
	provider, err = NewDNSPublicKeyProviderWithConfig(transport, config)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, lookupErr := provider.LookupPublicKey(context.Background(), query); lookupErr != nil {
			t.Fatal(lookupErr)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("disabled cache calls = %d", calls.Load())
	}
}

// TestDNSPublicKeyProviderRejectsInvalidConfiguration verifies public fail-closed mapping.
func TestDNSPublicKeyProviderRejectsInvalidConfiguration(t *testing.T) {
	transport := txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) { return TXTLookupResult{}, nil })
	for _, mutate := range []func(*DNSProviderConfig){
		func(config *DNSProviderConfig) { config.Limits.MaxCacheEntries = -1 },
		func(config *DNSProviderConfig) { config.Limits.MaxConcurrentLookups = 0 },
		func(config *DNSProviderConfig) { config.Limits.LookupTimeout = 31 * time.Second },
		func(config *DNSProviderConfig) { config.Clock = nil },
		func(config *DNSProviderConfig) { config.Parent = nil },
	} {
		config := DefaultDNSProviderConfig()
		mutate(&config)
		if _, err := NewDNSPublicKeyProviderWithConfig(transport, config); err == nil {
			t.Fatal("invalid DNS provider config accepted")
		}
	}
}

// mustPublicFoundLookup constructs one public found TXT fixture.
func mustPublicFoundLookup(t *testing.T, payload []byte) TXTLookupResult {
	t.Helper()
	result, err := NewFoundTXTLookupResult([][]byte{payload}, time.Minute, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// mustPublicAbsentLookup constructs one public absent TXT fixture.
func mustPublicAbsentLookup(t *testing.T) TXTLookupResult {
	t.Helper()
	result, err := NewAbsentTXTLookupResult(TXTAbsenceNODATA, time.Minute, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// mustPublicAmbiguousLookup constructs count-only public ambiguity.
func mustPublicAmbiguousLookup(t *testing.T) TXTLookupResult {
	t.Helper()
	result, err := NewAmbiguousTXTLookupResult(2, time.Minute, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
