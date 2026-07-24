package keyresolver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// FuzzOwnerConstruction verifies bounded deterministic owner validation and canonicalization.
func FuzzOwnerConstruction(f *testing.F) {
	for _, seed := range []struct {
		domain, selector string
		algorithm        byte
	}{
		{domain: "Example.TEST", selector: testSelector, algorithm: 0},
		{domain: "mail.example.test", selector: "march.2026", algorithm: 1},
		{domain: "example..test", selector: testSelector, algorithm: 0},
		{domain: testSigningDomain, selector: strings.Repeat("a", 64), algorithm: 0},
		{domain: "TOXIC-DOMAIN.example", selector: "TOXIC-SELECTOR", algorithm: 2},
		{domain: "exämple.test", selector: testSelector, algorithm: 0},
	} {
		f.Add([]byte(seed.domain), []byte(seed.selector), seed.algorithm)
	}
	f.Fuzz(func(t *testing.T, domainBytes, selectorBytes []byte, algorithmByte byte) {
		if len(domainBytes) > hardMaxNameBytes+1 || len(selectorBytes) > hardMaxNameBytes+1 {
			return
		}
		domainBefore := bytes.Clone(domainBytes)
		selectorBefore := bytes.Clone(selectorBytes)
		algorithm := fuzzAlgorithm(algorithmByte)
		first, firstErr := NewQuery(string(domainBytes), string(selectorBytes), algorithm, HardLimits())
		second, secondErr := NewQuery(string(domainBytes), string(selectorBytes), algorithm, HardLimits())
		if !bytes.Equal(domainBytes, domainBefore) || !bytes.Equal(selectorBytes, selectorBefore) {
			t.Fatal("owner construction mutated fuzz input")
		}
		if resolverErrorClass(firstErr) != resolverErrorClass(secondErr) || !reflect.DeepEqual(first, second) {
			t.Fatal("owner construction was nondeterministic")
		}
		if firstErr == nil {
			if !first.Algorithm().Known() || !ValidAbsoluteOwner(first.AbsoluteOwner()) || len(first.PresentationOwner()) > hardMaxNameBytes {
				t.Fatal("owner construction returned an invalid bounded query")
			}
		} else if !resolverErrorClass(firstErr).Known() || len(firstErr.Error()) > 64 {
			t.Fatal("owner construction returned an unbounded or unknown error")
		}
	})
}

// FuzzDNSKeyRecord verifies closed deterministic parsing, bounds, and immutable output.
func FuzzDNSKeyRecord(f *testing.F) {
	rsaDER := x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: big.NewInt(3233), E: 17})
	edRaw := bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize)
	for _, seed := range [][]byte{
		[]byte("p=" + base64.StdEncoding.EncodeToString(rsaDER)),
		[]byte("p=" + base64.RawStdEncoding.EncodeToString(rsaDER)),
		[]byte("v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(edRaw)),
		[]byte("v=DKIM1; k=ed25519; p=" + base64.RawStdEncoding.EncodeToString(edRaw)),
		[]byte("v=DKIM1; p=QQ==; p=QQ=="),
		[]byte("p=QUJDRA==; t=y\r\n \t:\r\n s"),
		[]byte("p=QUJDRA==; h=; n=note; s=odd; future-tag=value"),
		[]byte("v=DKIM1; k=rsa; p=QUJDRA==; q=dns-txt"),
		[]byte("p="),
		[]byte("p=%%%"),
		[]byte("p=AB=="),
		[]byte("p=TWF"),
		[]byte("p=QUI"),
		[]byte("p=QQ==\n"),
		[]byte("k=future-key; p=TOXIC-IGNORED"),
		[]byte("v=dkim1; p=QUJDRA=="),
		[]byte("future=x; v=DKIM1; p=QUJDRA=="),
		[]byte("p=QUJDRA==; h=a; h=b"),
		[]byte("p=QUJDRA==; future=a; future=b"),
		[]byte("p=QUJDRA==\r"),
		[]byte("p=QUJDRA==\n"),
		fuzzUniqueTagRecord(hardMaxTags + 1),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > hardMaxTXTRecordBytes+1 {
			return
		}
		before := bytes.Clone(input)
		first, firstErr := ParseRecord(input, HardLimits())
		second, secondErr := ParseRecord(bytes.Clone(input), HardLimits())
		if !bytes.Equal(input, before) {
			t.Fatal("record parser mutated fuzz input")
		}
		if RecordErrorCodeOf(firstErr) != RecordErrorCodeOf(secondErr) || firstErrString(firstErr) != firstErrString(secondErr) || !recordsEqual(first, second) {
			t.Fatal("record parsing was nondeterministic")
		}
		if firstErr != nil {
			if !RecordErrorCodeOf(firstErr).Known() || len(firstErr.Error()) > 96 || first.Valid() {
				t.Fatal("record parser returned an unbounded or contradictory error")
			}
			return
		}
		if !first.Valid() || len(first.PublicKeyData()) > hardMaxDecodedKeyBytes {
			t.Fatal("record parser returned invalid or oversized state")
		}
		material := first.PublicKeyData()
		if len(material) > 0 {
			material[0] ^= 0xff
			if !recordsEqual(first, second) {
				t.Fatal("record accessor exposed mutable storage")
			}
		}
	})
}

// FuzzTXTLookupTraversal verifies found, absent, ambiguous, and invalid transport shapes remain bounded.
func FuzzTXTLookupTraversal(f *testing.F) {
	for _, seed := range []struct {
		payload                []byte
		shape, dnssec, absence byte
		recordCount            int16
		ttl                    int64
	}{
		{payload: []byte("p=QUJDRA=="), shape: 0, dnssec: 0, recordCount: 1, ttl: int64(time.Minute)},
		{payload: []byte("p=QUJD"), shape: 1, dnssec: 1, recordCount: 2, ttl: 0},
		{shape: 2, dnssec: 2, absence: 0, ttl: int64(time.Minute)},
		{shape: 2, dnssec: 3, absence: 1, ttl: -1},
		{payload: []byte("TOXIC-TXT"), shape: 3, dnssec: 255, recordCount: 0, ttl: int64(^uint64(0) >> 1)},
	} {
		f.Add(seed.payload, seed.shape, seed.dnssec, seed.absence, seed.recordCount, seed.ttl)
	}
	f.Fuzz(func(t *testing.T, payload []byte, shape, dnssecByte, absenceByte byte, recordCount int16, ttlNanos int64) {
		if len(payload) > hardMaxTXTRecordBytes+1 {
			return
		}
		before := bytes.Clone(payload)
		first, firstErr := fuzzLookupResult(payload, shape, dnssecByte, absenceByte, recordCount, time.Duration(ttlNanos))
		second, secondErr := fuzzLookupResult(bytes.Clone(payload), shape, dnssecByte, absenceByte, recordCount, time.Duration(ttlNanos))
		if !bytes.Equal(payload, before) || resolverErrorClass(firstErr) != resolverErrorClass(secondErr) || !lookupResultsEqual(first, second) {
			t.Fatal("TXT result construction was mutable or nondeterministic")
		}
		if firstErr != nil {
			if !resolverErrorClass(firstErr).Known() || len(firstErr.Error()) > 64 || !first.IsZero() {
				t.Fatal("TXT result constructor returned contradictory error state")
			}
			return
		}
		valid := lookupResultValid(first)
		limits := DefaultLimits()
		limits.MaxCacheEntries = 0
		resolver, err := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) { return first, nil }), limits, WithResolverClock(func() time.Time { return time.Unix(1, 0) }))
		if err != nil {
			t.Fatal("fuzz resolver construction failed")
		}
		outcome, resolveErr := resolver.Resolve(context.Background(), testSigningDomain, testSelector, AlgorithmRSASHA256)
		if resolveErr != nil || !outcome.Valid() || !outcome.Status().Known() || !outcome.Algorithm().Known() {
			t.Fatal("TXT traversal returned an unknown or contradictory resolver outcome")
		}
		if !valid && outcome.Status() != KeyOutcomeProviderContract {
			t.Fatal("invalid TXT transport shape did not fail closed")
		}
		if first.RecordCount() < 0 || len(first.Records()) > 1 {
			t.Fatal("TXT result exposed unbounded payload traversal")
		}
		records := first.Records()
		if len(records) == 1 {
			copyValue := records[0].Payload()
			if len(copyValue) > 0 {
				copyValue[0] ^= 0xff
				if !lookupResultsEqual(first, second) {
					t.Fatal("TXT accessor exposed mutable payload")
				}
			}
		}
	})
}

// FuzzKeyDecodingCoherence verifies RSA/Ed25519 decoding, mismatch, and cloning properties.
func FuzzKeyDecodingCoherence(f *testing.F) {
	rsaDER := x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: big.NewInt(3233), E: 17})
	rsaSPKI, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: big.NewInt(3233), E: 17})
	if err != nil {
		f.Fatal("RSA SPKI seed construction failed")
	}
	rsaPrivate := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17}, D: big.NewInt(2753), Primes: []*big.Int{big.NewInt(61), big.NewInt(53)}}
	edSeed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	edPrivate := ed25519.NewKeyFromSeed(edSeed)
	edSPKI, err := x509.MarshalPKIXPublicKey(edPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		f.Fatal("Ed25519 SPKI seed construction failed")
	}
	edPKCS8, err := x509.MarshalPKCS8PrivateKey(edPrivate)
	if err != nil {
		f.Fatal("Ed25519 private seed construction failed")
	}
	certificateTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic.invalid"}, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(2, 0)}
	certificateDER, err := x509.CreateCertificate(bytes.NewReader(bytes.Repeat([]byte{0x5a}, 256)), certificateTemplate, certificateTemplate, edPrivate.Public(), edPrivate)
	if err != nil {
		f.Fatal("certificate seed construction failed")
	}
	for _, seed := range []struct {
		material           []byte
		keyType, algorithm byte
	}{
		{material: rsaDER, keyType: 0, algorithm: 0},
		{material: rsaSPKI, keyType: 0, algorithm: 0},
		{material: x509.MarshalPKCS1PrivateKey(rsaPrivate), keyType: 0, algorithm: 0},
		{material: certificateDER, keyType: 0, algorithm: 0},
		{material: append(bytes.Clone(rsaDER), 0), keyType: 0, algorithm: 0},
		{material: x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: big.NewInt(3232), E: 17}), keyType: 0, algorithm: 0},
		{material: x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: big.NewInt(3233), E: 18}), keyType: 0, algorithm: 0},
		{material: bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize), keyType: 1, algorithm: 1},
		{material: edSPKI, keyType: 1, algorithm: 1},
		{material: edPKCS8, keyType: 1, algorithm: 1},
		{material: []byte{0x30, 0x01, 0x00}, keyType: 0, algorithm: 0},
		{material: bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize-1), keyType: 1, algorithm: 1},
		{material: bytes.Repeat([]byte{0x42}, ed25519.PrivateKeySize), keyType: 1, algorithm: 1},
		{material: rsaDER, keyType: 0, algorithm: 1},
		{material: []byte("TOXIC-KEY"), keyType: 2, algorithm: 0},
		{material: nil, keyType: 3, algorithm: 0},
	} {
		f.Add(seed.material, seed.keyType, seed.algorithm)
	}
	f.Fuzz(func(t *testing.T, material []byte, keyTypeByte, algorithmByte byte) {
		if len(material) > hardMaxDecodedKeyBytes+1 {
			return
		}
		before := bytes.Clone(material)
		record := fuzzKeyRecord(material, keyTypeByte)
		algorithm := fuzzAlgorithm(algorithmByte)
		first, firstErr := DecodeKey(record, algorithm)
		second, secondErr := DecodeKey(record, algorithm)
		if !bytes.Equal(material, before) || resolverErrorClass(firstErr) != resolverErrorClass(secondErr) || !keyOutcomesEqual(first, second) {
			t.Fatal("key decoding was mutable or nondeterministic")
		}
		if firstErr != nil {
			if !resolverErrorClass(firstErr).Known() || !first.IsZero() || len(firstErr.Error()) > 64 {
				t.Fatal("key decoding returned contradictory error state")
			}
			return
		}
		if !first.Valid() || !first.Status().Known() || !first.Algorithm().Known() {
			t.Fatal("key decoding returned unknown state")
		}
		mutateKeyMaterial(first.Material())
		if !keyOutcomesEqual(first, second) {
			t.Fatal("key material accessor exposed mutable storage")
		}
	})
}

// fuzzAlgorithm maps arbitrary bytes onto supported and unknown algorithm states.
func fuzzAlgorithm(value byte) Algorithm {
	switch value % 3 {
	case 0:
		return AlgorithmRSASHA256
	case 1:
		return AlgorithmEd25519SHA256
	default:
		return Algorithm("unknown")
	}
}

// resolverErrorClass returns the closed resolver class or zero for nil/unknown errors.
func resolverErrorClass(err error) ErrorClass {
	for _, class := range []ErrorClass{ErrorClassContract, ErrorClassPermanent} {
		if IsErrorClass(err, class) {
			return class
		}
	}
	return ""
}

// firstErrString returns bounded deterministic error text without formatting fuzz input.
func firstErrString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// recordsEqual compares only bounded record facts and detached material.
func recordsEqual(left, right Record) bool {
	return left.Draft() == right.Draft() && left.Status() == right.Status() && left.KeyType() == right.KeyType() &&
		left.Metadata() == right.Metadata() && bytes.Equal(left.PublicKeyData(), right.PublicKeyData()) && left.Valid() == right.Valid()
}

// fuzzLookupResult constructs one fuzz-selected public transport shape without unbounded payload slices.
func fuzzLookupResult(payload []byte, shape, dnssecByte, absenceByte byte, recordCount int16, ttl time.Duration) (LookupResult, error) {
	dnssecValues := []DNSSECStatus{DNSSECStatusSecure, DNSSECStatusInsecure, DNSSECStatusBogus, DNSSECStatusIndeterminate, DNSSECStatusUnavailable, DNSSECStatus("unknown")}
	dnssec := dnssecValues[int(dnssecByte)%len(dnssecValues)]
	switch shape % 10 {
	case 0:
		return NewFoundResult([][]byte{payload}, ttl, dnssec)
	case 1:
		return NewAmbiguousResult(int(recordCount), ttl, dnssec)
	case 2:
		absenceValues := []AbsenceClass{AbsenceNXDOMAIN, AbsenceNODATA, AbsenceClass("unknown")}
		return NewAbsentResult(absenceValues[int(absenceByte)%len(absenceValues)], ttl, dnssec)
	case 3:
		return NewFoundResult(nil, ttl, dnssec)
	case 4:
		return LookupResult{}, nil
	case 5:
		return LookupResult{status: LookupStatusFound, recordCount: 1, records: []TXTRecord{newTXTRecord(payload)}, absence: AbsenceNXDOMAIN, positiveTTL: ttl, dnssec: dnssec}, nil
	case 6:
		return LookupResult{status: LookupStatusAbsent, recordCount: 1, records: []TXTRecord{newTXTRecord(payload)}, absence: AbsenceNODATA, negativeTTL: ttl, dnssec: dnssec}, nil
	case 7:
		return LookupResult{status: LookupStatusFound, recordCount: 1, positiveTTL: ttl, dnssec: dnssec}, nil
	case 8:
		return LookupResult{status: LookupStatus("unknown"), recordCount: 1, records: []TXTRecord{newTXTRecord(payload)}, positiveTTL: ttl, dnssec: dnssec}, nil
	default:
		return LookupResult{status: LookupStatusFound, recordCount: 1, records: []TXTRecord{newTXTRecord(payload)}, positiveTTL: ttl, negativeTTL: time.Second, dnssec: dnssec}, nil
	}
}

// fuzzUniqueTagRecord constructs a bounded record with genuinely distinct tag names.
func fuzzUniqueTagRecord(count int) []byte {
	var builder strings.Builder
	for index := 0; index < count; index++ {
		builder.WriteString("x")
		builder.WriteString(strconv.Itoa(index))
		builder.WriteString("=a;")
	}
	builder.WriteString("p=")
	return []byte(builder.String())
}

// lookupResultsEqual compares bounded transport facts and detached unique payloads.
func lookupResultsEqual(left, right LookupResult) bool {
	return left.Status() == right.Status() && left.RecordCount() == right.RecordCount() && left.Absence() == right.Absence() &&
		left.PositiveTTL() == right.PositiveTTL() && left.NegativeTTL() == right.NegativeTTL() && left.DNSSECStatus() == right.DNSSECStatus() &&
		reflect.DeepEqual(left.Records(), right.Records()) && left.IsZero() == right.IsZero()
}

// fuzzKeyRecord constructs supported, unsupported, revoked, or invalid injected record state.
func fuzzKeyRecord(material []byte, keyTypeByte byte) Record {
	metadata := newMetadata(keyTypeByte&4 != 0, keyTypeByte&8 != 0)
	switch keyTypeByte % 5 {
	case 0:
		return keyDataRecord(KeyTypeRSA, material, metadata)
	case 1:
		return keyDataRecord(KeyTypeEd25519, material, metadata)
	case 2:
		return Record{draft: DNSDraftIdentifier, status: RecordStatusUnsupportedKeyType, keyType: KeyTypeUnsupported, metadata: metadata, initialized: true}
	case 3:
		return Record{draft: DNSDraftIdentifier, status: RecordStatusRevoked, keyType: KeyTypeRSA, metadata: metadata, initialized: true}
	default:
		return Record{}
	}
}

// keyOutcomesEqual compares bounded key facts and cloned material.
func keyOutcomesEqual(left, right KeyOutcome) bool {
	return left.Status() == right.Status() && left.Algorithm() == right.Algorithm() && left.Metadata() == right.Metadata() &&
		reflect.DeepEqual(left.Material(), right.Material()) && left.Valid() == right.Valid() && left.IsZero() == right.IsZero()
}

// mutateKeyMaterial modifies only detached accessor material.
func mutateKeyMaterial(material any) {
	switch key := material.(type) {
	case *rsa.PublicKey:
		if key != nil && key.N != nil {
			key.N.SetInt64(1)
		}
	case ed25519.PublicKey:
		if len(key) > 0 {
			key[0] ^= 0xff
		}
	}
}
