package dkim2

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDNSProviderDiagnosticsDiscardToxicMatrix verifies DNS/query/provider inputs never enter public diagnostics.
func TestDNSProviderDiagnosticsDiscardToxicMatrix(t *testing.T) {
	const marker = "PUBLIC-DNS-TOXIC-MARKER"
	transport := txtTransportFunc(func(_ context.Context, owner string) (TXTLookupResult, error) {
		return TXTLookupResult{}, errors.New(marker + owner)
	})
	provider, err := NewDNSPublicKeyProvider(transport)
	if err != nil {
		t.Fatal("privacy provider construction failed")
	}
	for _, query := range []PublicKeyQuery{
		newPublicKeyQuery(marker+"/example.test", "selector", AlgorithmRSASHA256),
		newPublicKeyQuery("example.test", marker+"/selector", AlgorithmRSASHA256),
		newPublicKeyQuery("example.test", "selector", AlgorithmRSASHA256),
	} {
		result, lookupErr := provider.LookupPublicKey(context.Background(), query)
		assertPublicDNSMarkerAbsent(t, marker, fmt.Sprintf("%v %#v %v %v", lookupErr, result, result.Status(), result.KeyPolicyMetadata()))
	}

	for _, record := range []string{
		"p=%%%" + marker,
		"p=QQ==; n=" + marker,
		"p=QQ==; future-tag=" + marker,
		"p=QQ==; t=y:" + marker,
		"k=future-key; p=" + marker,
	} {
		lookup, lookupErr := NewFoundTXTLookupResult([][]byte{[]byte(record)}, time.Minute, DNSSECStatusUnavailable)
		if lookupErr != nil {
			t.Fatal("toxic record fixture construction failed")
		}
		caseProvider, constructErr := NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) { return lookup, nil }))
		if constructErr != nil {
			t.Fatal("toxic record provider construction failed")
		}
		result, caseErr := caseProvider.LookupPublicKey(context.Background(), newPublicKeyQuery("example.test", "selector", AlgorithmRSASHA256))
		assertPublicDNSMarkerAbsent(t, marker, fmt.Sprintf("%v %#v %v %v", caseErr, result, result.Status(), result.KeyPolicyMetadata()))
	}

	const cacheMarker = "public-dns-toxic-cache-key"
	encodedMarker := base64.StdEncoding.EncodeToString([]byte(cacheMarker))
	chunks := [][]byte{[]byte("p=" + encodedMarker[:len(encodedMarker)/2]), []byte(encodedMarker[len(encodedMarker)/2:])}
	joined := bytes.Join(chunks, nil)
	lookup, lookupErr := NewFoundTXTLookupResult([][]byte{joined}, time.Minute, DNSSECStatusUnavailable)
	if lookupErr != nil {
		t.Fatal("chunk privacy lookup construction failed")
	}
	for _, chunk := range chunks {
		for index := range chunk {
			chunk[index] ^= byte(index + 1)
		}
	}
	calls := 0
	cacheProvider, constructErr := NewDNSPublicKeyProvider(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) {
		calls++
		return lookup, nil
	}))
	if constructErr != nil {
		t.Fatal("cache-key privacy provider construction failed")
	}
	for range 2 {
		result, caseErr := cacheProvider.LookupPublicKey(context.Background(), newPublicKeyQuery("example.test", cacheMarker, AlgorithmRSASHA256))
		if caseErr != nil || result.Status() != PublicKeyStatusInvalid {
			t.Fatal("valid Base64 toxic key bytes did not fail as structured invalid state")
		}
		formatted := fmt.Sprintf("%v %#v %v %v", caseErr, result, result.Status(), result.KeyPolicyMetadata())
		assertPublicDNSMarkerAbsent(t, cacheMarker, formatted)
		assertPublicDNSMarkerAbsent(t, encodedMarker, formatted)
	}
	if calls != 1 {
		t.Fatal("stable invalid privacy result did not exercise the cache key")
	}
}

// TestDNSProviderConcurrentMutationIsolation verifies detached TXT, key, metadata, cache, and result storage.
func TestDNSProviderConcurrentMutationIsolation(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	manifest := loadDNSGoldenManifest(t, corpus)
	rsaSource := []byte(manifest.RSATestingStrictTXT)
	edSource := []byte(manifest.Ed25519LowerTXT + "; t=y:s")
	rsaLookup, err := NewFoundTXTLookupResult([][]byte{rsaSource}, time.Minute, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatal("RSA mutation fixture construction failed")
	}
	edLookup, err := NewFoundTXTLookupResult([][]byte{edSource}, time.Minute, DNSSECStatusUnavailable)
	if err != nil {
		t.Fatal("Ed25519 mutation fixture construction failed")
	}
	provider, err := NewDNSPublicKeyProvider(txtTransportFunc(func(_ context.Context, owner string) (TXTLookupResult, error) {
		if owner == dnsVectorRSAOwner {
			return rsaLookup, nil
		}
		return edLookup, nil
	}))
	if err != nil {
		t.Fatal("mutation provider construction failed")
	}

	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for index := range rsaSource {
			rsaSource[index] ^= byte(index + 1)
		}
	}()
	go func() {
		defer workers.Done()
		for index := range edSource {
			edSource[index] ^= byte(index + 1)
		}
	}()
	for range 16 {
		workers.Go(func() {
			for range 32 {
				for _, tt := range []struct {
					query  PublicKeyQuery
					lookup TXTLookupResult
				}{
					{query: newPublicKeyQuery("example.test", "rsa.test", AlgorithmRSASHA256), lookup: rsaLookup},
					{query: newPublicKeyQuery("example.test", "ed.test", AlgorithmEd25519SHA256), lookup: edLookup},
				} {
					result, lookupErr := provider.LookupPublicKey(context.Background(), tt.query)
					metadata := result.KeyPolicyMetadata()
					if lookupErr != nil || result.Status() != PublicKeyStatusFound || !metadata.TestingDeclared() || !metadata.StrictIdentityDeclared() || metadata.StrictIdentityApplicable() {
						t.Error("concurrent DNS result lost immutable facts")
						return
					}
					mutatePublicKeyResult(result)
					records := tt.lookup.Records()
					payload := records[0].Payload()
					payload[0] ^= 0xff
				}
			}
		})
	}
	workers.Wait()
	if !bytes.Equal(rsaLookup.Records()[0].Payload(), []byte(manifest.RSATestingStrictTXT)) || !bytes.Equal(edLookup.Records()[0].Payload(), []byte(manifest.Ed25519LowerTXT+"; t=y:s")) {
		t.Fatal("caller or accessor mutation reached owned TXT storage")
	}
}

// assertPublicDNSMarkerAbsent fails without repeating protected diagnostic content.
func assertPublicDNSMarkerAbsent(t *testing.T, marker, text string) {
	t.Helper()
	if strings.Contains(text, marker) {
		t.Fatal("public DNS diagnostic leaked protected input")
	}
}
