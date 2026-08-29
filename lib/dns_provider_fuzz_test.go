package dkim2

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"
)

// FuzzDNSPublicProvider verifies the public DNS provider remains closed, deterministic, and secret-safe.
func FuzzDNSPublicProvider(f *testing.F) {
	for _, seed := range []struct {
		record                   []byte
		shape, algorithm, dnssec byte
	}{
		{record: []byte("p="), shape: 0, algorithm: 0, dnssec: 0},
		{record: []byte("v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), shape: 0, algorithm: 1, dnssec: 1},
		{record: []byte("v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), shape: 0, algorithm: 1, dnssec: 1},
		{record: []byte("p=QQ==; p=QQ=="), shape: 0, algorithm: 0, dnssec: 2},
		{record: []byte("p=%%%TOXIC-TXT"), shape: 0, algorithm: 0, dnssec: 3},
		{record: []byte("future=TOXIC-NOTE; p=QQ==; t=y:s:future"), shape: 0, algorithm: 0, dnssec: 4},
		{record: nil, shape: 1, algorithm: 0, dnssec: 0},
		{record: nil, shape: 2, algorithm: 0, dnssec: 0},
		{record: nil, shape: 3, algorithm: 0, dnssec: 0},
		{record: []byte("TOXIC-CONTRADICTORY"), shape: 6, algorithm: 2, dnssec: 255},
	} {
		f.Add(seed.record, seed.shape, seed.algorithm, seed.dnssec)
	}
	f.Fuzz(func(t *testing.T, record []byte, shape, algorithmByte, dnssecByte byte) {
		if len(record) > hardMaxTXTRecordPayloadBytes+1 {
			return
		}
		before := bytes.Clone(record)
		lookup, transportErr := fuzzPublicLookup(record, shape, dnssecByte)
		transport := txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) {
			return lookup, transportErr
		})
		config := DefaultDNSProviderConfig()
		config.Limits.MaxCacheEntries = 0
		provider, err := NewDNSPublicKeyProviderWithConfig(transport, config)
		if err != nil {
			t.Fatal("public fuzz provider construction failed")
		}
		algorithm := fuzzPublicAlgorithm(algorithmByte)
		query := newPublicKeyQuery("example.test", "selector", algorithm)
		first, firstErr := provider.LookupPublicKey(context.Background(), query)
		second, secondErr := provider.LookupPublicKey(context.Background(), query)
		if !bytes.Equal(record, before) || publicErrorClass(firstErr) != publicErrorClass(secondErr) || !publicKeyResultsEqual(first, second) {
			t.Fatal("public DNS provider was mutable or nondeterministic")
		}
		if firstErr != nil {
			if !first.IsZero() || len(firstErr.Error()) > 96 || !publicErrorClass(firstErr).known {
				t.Fatal("public DNS provider returned contradictory or unbounded error state")
			}
			return
		}
		if first.IsZero() || !first.Status().Known() || !first.Algorithm().Known() {
			t.Fatal("public DNS provider returned unknown structured state")
		}
		mutatePublicKeyResult(first)
		if !publicKeyResultsEqual(first, second) {
			t.Fatal("public DNS provider accessor exposed mutable storage")
		}
	})
}

// FuzzDNSPublicVerifier verifies hostile DNS states remain structured through the public verifier.
func FuzzDNSPublicVerifier(f *testing.F) {
	corpusBytes, err := os.ReadFile("testdata/vectors/draft-ietf-dkim-dkim2-spec-06/public-golden.json")
	if err != nil {
		f.Fatal("public verifier fuzz corpus unavailable")
	}
	var corpus publicGoldenCorpus
	if json.Unmarshal(corpusBytes, &corpus) != nil || corpus.Draft != DraftIdentifier {
		f.Fatal("public verifier fuzz corpus invalid")
	}
	vector, ok := corpus.Vectors[goldenVectorRSAPass]
	if !ok {
		f.Fatal("public verifier fuzz seed missing")
	}
	message, err := base64.StdEncoding.DecodeString(vector.Raw)
	if err != nil {
		f.Fatal("public verifier fuzz message invalid")
	}
	reverse, err := base64.StdEncoding.DecodeString(vector.Reverse)
	if err != nil {
		f.Fatal("public verifier fuzz reverse path invalid")
	}
	forward := make([][]byte, len(vector.Forward))
	for index := range vector.Forward {
		forward[index], err = base64.StdEncoding.DecodeString(vector.Forward[index])
		if err != nil {
			f.Fatal("public verifier fuzz forward path invalid")
		}
	}
	for _, seed := range []struct {
		record        []byte
		shape, dnssec byte
	}{
		{record: []byte("p="), shape: 0, dnssec: 0},
		{record: []byte("p=%%%TOXIC-DNS-VERIFY"), shape: 0, dnssec: 1},
		{record: []byte("k=future; p=TOXIC-IGNORED; t=y:s"), shape: 0, dnssec: 2},
		{shape: 1, dnssec: 3},
		{shape: 2, dnssec: 4},
		{shape: 3, dnssec: 0},
		{shape: 5, dnssec: 0},
		{record: []byte("TOXIC-CONTRADICTORY"), shape: 11, dnssec: 255},
	} {
		f.Add(seed.record, seed.shape, seed.dnssec)
	}
	f.Fuzz(func(t *testing.T, record []byte, shape, dnssecByte byte) {
		if len(record) > hardMaxTXTRecordPayloadBytes+1 {
			return
		}
		before := bytes.Clone(record)
		lookup, transportErr := fuzzPublicLookup(record, shape, dnssecByte)
		config := DefaultDNSProviderConfig()
		config.Limits.MaxCacheEntries = 0
		provider, constructErr := NewDNSPublicKeyProviderWithConfig(txtTransportFunc(func(context.Context, string) (TXTLookupResult, error) { return lookup, transportErr }), config)
		if constructErr != nil {
			t.Fatal("public verifier fuzz provider construction failed")
		}
		verifier, constructErr := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
		if constructErr != nil {
			t.Fatal("public verifier fuzz construction failed")
		}
		first, firstErr := verifier.Verify(context.Background(), NewVerifyRequest(message, reverse, forward))
		second, secondErr := verifier.Verify(context.Background(), NewVerifyRequest(message, reverse, forward))
		if !bytes.Equal(record, before) || publicErrorClass(firstErr) != publicErrorClass(secondErr) || !reflect.DeepEqual(snapshotPublicResult(first), snapshotPublicResult(second)) {
			t.Fatal("public DNS verifier was mutable or nondeterministic")
		}
		if firstErr != nil || !first.State().Known() || !first.PrimaryReason().Known() || first.CheckCount() > 32 || first.SignatureSetCount() > 8 {
			t.Fatal("public DNS verifier violated structured bounded result/error disjointness")
		}
		for _, check := range first.Checks() {
			if !check.Class().Known() || !check.Reason().Known() {
				t.Fatal("public DNS verifier returned unknown check facts")
			}
		}
		for _, signature := range first.SignatureSets() {
			if !signature.Algorithm().Known() || !signature.Status().Known() || !signature.Reason().Known() {
				t.Fatal("public DNS verifier returned unknown signature facts")
			}
		}
	})
}

type publicFuzzErrorClass struct {
	api      APIErrorCode
	provider ProviderErrorClass
	known    bool
}

// publicErrorClass returns only bounded public error classification.
func publicErrorClass(err error) publicFuzzErrorClass {
	if err == nil {
		return publicFuzzErrorClass{known: true}
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Code().Known() {
		return publicFuzzErrorClass{api: apiErr.Code(), known: true}
	}
	if class := ProviderErrorClassOf(err); class.Known() {
		return publicFuzzErrorClass{provider: class, known: true}
	}
	return publicFuzzErrorClass{}
}

// fuzzPublicLookup constructs found, absent, ambiguous, typed-error, raw-error, and contradictory cases.
func fuzzPublicLookup(record []byte, shape, dnssecByte byte) (TXTLookupResult, error) {
	dnssecValues := []DNSSECStatus{DNSSECStatusSecure, DNSSECStatusInsecure, DNSSECStatusBogus, DNSSECStatusIndeterminate, DNSSECStatusUnavailable, DNSSECStatus("unknown")}
	dnssec := dnssecValues[int(dnssecByte)%len(dnssecValues)]
	switch shape % 12 {
	case 0:
		return NewFoundTXTLookupResult([][]byte{record}, time.Minute, dnssec)
	case 1:
		return NewAmbiguousTXTLookupResult(2, time.Minute, dnssec)
	case 2:
		return NewAbsentTXTLookupResult(TXTAbsenceNXDOMAIN, time.Minute, dnssec)
	case 3:
		return TXTLookupResult{}, NewTemporaryProviderError()
	case 4:
		return TXTLookupResult{}, NewPermanentProviderError()
	case 5:
		return TXTLookupResult{}, errors.New("TOXIC-RAW-RESOLVER-ENDPOINT")
	case 6:
		lookup, _ := NewFoundTXTLookupResult([][]byte{record}, time.Minute, DNSSECStatusUnavailable)
		return lookup, NewTemporaryProviderError()
	case 7:
		return TXTLookupResult{}, nil
	case 8:
		return TXTLookupResult{state: &txtLookupResultState{
			status: TXTLookupStatusFound, records: []TXTRecord{newTXTRecord(record)},
			recordCount: 1, absence: TXTAbsenceNXDOMAIN, positiveTTL: time.Minute, dnssec: dnssec,
		}}, nil
	case 9:
		return TXTLookupResult{state: &txtLookupResultState{
			status: TXTLookupStatusAbsent, records: []TXTRecord{newTXTRecord(record)},
			recordCount: 1, absence: TXTAbsenceNODATA, negativeTTL: time.Minute, dnssec: dnssec,
		}}, nil
	case 10:
		return TXTLookupResult{state: &txtLookupResultState{
			status: TXTLookupStatus("unknown"), records: []TXTRecord{newTXTRecord(record)},
			recordCount: 1, positiveTTL: time.Minute, dnssec: DNSSECStatus("unknown"),
		}}, nil
	default:
		return TXTLookupResult{state: &txtLookupResultState{
			status: TXTLookupStatusFound, records: []TXTRecord{newTXTRecord(record)},
			recordCount: 2, positiveTTL: time.Minute, negativeTTL: time.Second, dnssec: dnssec,
		}}, nil
	}
}

// fuzzPublicAlgorithm maps arbitrary bytes onto supported and unknown query algorithms.
func fuzzPublicAlgorithm(value byte) Algorithm {
	switch value % 3 {
	case 0:
		return AlgorithmRSASHA256
	case 1:
		return AlgorithmEd25519SHA256
	default:
		return Algorithm("unknown")
	}
}

// publicKeyResultsEqual compares bounded facts and detached public material.
func publicKeyResultsEqual(left, right PublicKeyResult) bool {
	leftRSA, leftRSAOK := left.RSAPublicKey()
	rightRSA, rightRSAOK := right.RSAPublicKey()
	leftEd, leftEdOK := left.Ed25519PublicKey()
	rightEd, rightEdOK := right.Ed25519PublicKey()
	return left.Status() == right.Status() && left.Algorithm() == right.Algorithm() && left.KeyPolicyMetadata() == right.KeyPolicyMetadata() &&
		leftRSAOK == rightRSAOK && leftEdOK == rightEdOK && reflect.DeepEqual(leftRSA, rightRSA) && bytes.Equal(leftEd, rightEd) && left.IsZero() == right.IsZero()
}

// mutatePublicKeyResult modifies only detached public accessors.
func mutatePublicKeyResult(result PublicKeyResult) {
	if key, ok := result.RSAPublicKey(); ok && key.N != nil {
		key.N.SetInt64(1)
	}
	if key, ok := result.Ed25519PublicKey(); ok && len(key) > 0 {
		key[0] ^= 0xff
	}
}
