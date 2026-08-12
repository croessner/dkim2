package dkim2

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

const (
	dnsVectorRSAOwner = "rsa.test._domainkey.example.test."
	dnsVectorEdOwner  = "ed.test._domainkey.example.test."
)

type dnsGoldenManifest struct {
	MessageDraft        string   `json:"message_draft"`
	DNSDraft            string   `json:"dns_draft"`
	RSAPKCS1            string   `json:"rsa_pkcs1_der_base64"`
	Ed25519Raw          string   `json:"ed25519_raw_base64"`
	RSADefaultTXT       string   `json:"rsa_default_txt"`
	RSAExplicitTXT      string   `json:"rsa_explicit_txt"`
	Ed25519LowerTXT     string   `json:"ed25519_lowercase_txt"`
	RSATestingTXT       string   `json:"rsa_testing_txt"`
	RSAStrictTXT        string   `json:"rsa_strict_txt"`
	RSATestingStrictTXT string   `json:"rsa_testing_strict_txt"`
	Owners              []string `json:"owners"`
}

type dnsVectorTransport struct {
	lookup func(context.Context, string) (TXTLookupResult, error)
	calls  atomic.Int32
}

// LookupTXT resolves one synthetic public vector owner without network access.
func (t *dnsVectorTransport) LookupTXT(ctx context.Context, owner string) (TXTLookupResult, error) {
	t.calls.Add(1)
	return t.lookup(ctx, owner)
}

type publicResultSnapshot struct {
	Draft                string
	State                ResultState
	Scope                VerificationScope
	HistoricalContent    HistoricalState
	HistoricalSignatures HistoricalState
	Reason               ReasonCode
	Custody              CustodyStructure
	Target               [2]uint64
	Checks               []publicCheckSnapshot
	Signatures           []publicSignatureSnapshot
}

type publicCheckSnapshot struct {
	Class  CheckClass
	Reason ReasonCode
}

type publicSignatureSnapshot struct {
	Algorithm  Algorithm
	Status     SignatureStatus
	Reason     ReasonCode
	Testing    bool
	Strict     bool
	Applicable bool
}

// TestDNSDraft04PublicPassVectors verifies RSA, Ed25519, combined, and default key tags.
func TestDNSDraft04PublicPassVectors(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	manifest := loadDNSGoldenManifest(t, corpus)
	tests := []struct {
		name      string
		vector    string
		rsaRecord string
	}{
		{name: "rsa omitted version and key type", vector: goldenVectorRSAPass, rsaRecord: manifest.RSADefaultTXT},
		{name: "rsa explicit version and key type", vector: goldenVectorRSAPass, rsaRecord: manifest.RSAExplicitTXT},
		{name: "ed25519 lowercase key type", vector: goldenVectorEd25519Pass, rsaRecord: manifest.RSADefaultTXT},
		{name: "both supported", vector: "both_pass", rsaRecord: manifest.RSADefaultTXT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := dnsPassTransport(t, tt.rsaRecord, manifest.Ed25519LowerTXT, DNSSECStatusUnavailable)
			provider := mustDNSVectorProvider(t, transport, DefaultDNSProviderConfig())
			got := verifyDNSVector(context.Background(), t, corpus, tt.vector, provider)
			static := verifyDNSVector(context.Background(), t, corpus, tt.vector, publicGoldenProvider{mode: goldenProviderKeys, rsa: corpus.rsaKey(t), ed: corpus.edKey(t)})
			if !reflect.DeepEqual(snapshotPublicResult(got), snapshotPublicResult(static)) {
				t.Fatalf("DNS and static public facts differ: state=%q/%q", got.State(), static.State())
			}
		})
	}
}

// TestDNSDraft04PublicStateMatrix verifies every DNS/provider classification through the facade.
func TestDNSDraft04PublicStateMatrix(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	manifest := loadDNSGoldenManifest(t, corpus)
	tests := []struct {
		name      string
		lookup    func(context.Context, string) (TXTLookupResult, error)
		state     ResultState
		reason    ReasonCode
		sigReason ReasonCode
		class     CheckClass
		status    SignatureStatus
	}{
		{name: "nxdomain", lookup: fixedPublicAbsent(t, TXTAbsenceNXDOMAIN), state: ResultStatePERMERROR, reason: ReasonMissingKey, sigReason: ReasonMissingKey, class: CheckClassKey, status: SignatureStatusPERMERROR},
		{name: "nodata", lookup: fixedPublicAbsent(t, TXTAbsenceNODATA), state: ResultStatePERMERROR, reason: ReasonMissingKey, sigReason: ReasonMissingKey, class: CheckClassKey, status: SignatureStatusPERMERROR},
		{name: testNameRevoked, lookup: fixedPublicRecord(t, "p="), state: ResultStatePERMERROR, reason: ReasonRevokedKey, sigReason: ReasonRevokedKey, class: CheckClassKey, status: SignatureStatusPERMERROR},
		{name: "malformed tag", lookup: fixedPublicRecord(t, "p=QQ==; p=QQ=="), state: ResultStatePERMERROR, reason: ReasonInvalidKey, sigReason: ReasonInvalidKey, class: CheckClassKey, status: SignatureStatusPERMERROR},
		{name: "malformed base64", lookup: fixedPublicRecord(t, "p=%%%"), state: ResultStatePERMERROR, reason: ReasonInvalidKey, sigReason: ReasonInvalidKey, class: CheckClassKey, status: SignatureStatusPERMERROR},
		{name: "malformed der", lookup: fixedPublicRecord(t, "p=QQ=="), state: ResultStatePERMERROR, reason: ReasonInvalidKey, sigReason: ReasonInvalidKey, class: CheckClassKey, status: SignatureStatusPERMERROR},
		{name: testNameAmbiguous, lookup: fixedPublicAmbiguous(t), state: ResultStatePERMERROR, reason: ReasonAmbiguousKey, sigReason: ReasonAmbiguousKey, class: CheckClassKey, status: SignatureStatusPERMERROR},
		{name: "unsupported key type", lookup: fixedPublicRecord(t, "k=future; p=QQ=="), state: ResultStatePERMERROR, reason: ReasonUnsupportedKeyType, sigReason: ReasonUnsupportedKeyType, class: CheckClassKey, status: SignatureStatusPERMERROR},
		{name: "algorithm mismatch", lookup: fixedPublicRecord(t, "k=ed25519; p="+manifest.Ed25519Raw), state: ResultStatePERMERROR, reason: ReasonKeyAlgorithmMismatch, sigReason: ReasonKeyAlgorithmMismatch, class: CheckClassKey, status: SignatureStatusPERMERROR},
		{name: "typed temporary", lookup: fixedPublicError(NewTemporaryProviderError()), state: ResultStateTEMPERROR, reason: ReasonProviderTemporary, sigReason: ReasonProviderTemporary, class: CheckClassProvider, status: SignatureStatusTEMPERROR},
		{name: "typed permanent", lookup: fixedPublicError(NewPermanentProviderError()), state: ResultStatePERMERROR, reason: ReasonProviderPermanent, sigReason: ReasonProviderPermanent, class: CheckClassProvider, status: SignatureStatusPERMERROR},
		{name: "provider contract", lookup: fixedPublicError(errors.New("synthetic bounded failure")), state: ResultStatePERMERROR, reason: ReasonProviderContract, sigReason: ReasonProviderContract, class: CheckClassProvider, status: SignatureStatusPERMERROR},
		{name: "unclassified transport deadline", lookup: fixedPublicError(context.DeadlineExceeded), state: ResultStatePERMERROR, reason: ReasonProviderContract, sigReason: ReasonProviderContract, class: CheckClassProvider, status: SignatureStatusPERMERROR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &dnsVectorTransport{lookup: tt.lookup}
			result := verifyDNSVector(context.Background(), t, corpus, goldenVectorRSAPass, mustDNSVectorProvider(t, transport, DefaultDNSProviderConfig()))
			if result.State() != tt.state || result.PrimaryReason() != tt.reason {
				t.Fatalf("state/reason = %q/%q", result.State(), result.PrimaryReason())
			}
			signatures := result.SignatureSets()
			if len(signatures) != 1 {
				t.Fatalf("signature count = %d", len(signatures))
			}
			if signatures[0].Reason() != tt.sigReason || signatures[0].Status() != tt.status {
				t.Fatalf("signature = %q/%q", signatures[0].Status(), signatures[0].Reason())
			}
			if got, want := snapshotPublicResult(result).Checks, expectedDNSStateChecks(tt.class, tt.reason); !reflect.DeepEqual(got, want) {
				t.Fatalf("checks = %#v want %#v", got, want)
			}
		})
	}
}

// TestDNSDraft04MetadataIsVerdictNeutral verifies t=y, t=s, and combined declarations.
func TestDNSDraft04MetadataIsVerdictNeutral(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	manifest := loadDNSGoldenManifest(t, corpus)
	baseline := verifyDNSVector(context.Background(), t, corpus, goldenVectorRSAPass, mustDNSVectorProvider(t, dnsPassTransport(t, manifest.RSADefaultTXT, manifest.Ed25519LowerTXT, DNSSECStatusUnavailable), DefaultDNSProviderConfig()))
	baselineSnapshot := snapshotPublicResult(baseline)
	for _, tt := range []struct {
		name, record    string
		testing, strict bool
	}{
		{name: "testing", record: manifest.RSATestingTXT, testing: true},
		{name: "strict", record: manifest.RSAStrictTXT, strict: true},
		{name: "combined", record: manifest.RSATestingStrictTXT, testing: true, strict: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := verifyDNSVector(context.Background(), t, corpus, goldenVectorRSAPass, mustDNSVectorProvider(t, dnsPassTransport(t, tt.record, manifest.Ed25519LowerTXT, DNSSECStatusUnavailable), DefaultDNSProviderConfig()))
			metadata := result.SignatureSets()[0].KeyPolicyMetadata()
			if metadata.TestingDeclared() != tt.testing || metadata.StrictIdentityDeclared() != tt.strict || metadata.StrictIdentityApplicable() {
				t.Fatalf("metadata = testing %v strict %v applicable %v", metadata.TestingDeclared(), metadata.StrictIdentityDeclared(), metadata.StrictIdentityApplicable())
			}
			expected := baselineSnapshot
			expected.Signatures = slices.Clone(baselineSnapshot.Signatures)
			expected.Signatures[0].Testing = tt.testing
			expected.Signatures[0].Strict = tt.strict
			if !reflect.DeepEqual(snapshotPublicResult(result), expected) {
				t.Fatal("metadata changed a verdict fact")
			}
		})
	}
	static := verifyDNSVector(context.Background(), t, corpus, goldenVectorRSAPass, publicGoldenProvider{mode: goldenProviderKeys, rsa: corpus.rsaKey(t), ed: corpus.edKey(t)})
	if metadata := static.SignatureSets()[0].KeyPolicyMetadata(); metadata.TestingDeclared() || metadata.StrictIdentityDeclared() || metadata.StrictIdentityApplicable() {
		t.Fatalf("static provider metadata was nonzero: %#v", metadata)
	}

	for _, tt := range []struct {
		name, record string
		reason       ReasonCode
	}{
		{name: "revoked", record: "p=; t=y:s", reason: ReasonRevokedKey},
		{name: testNameInvalid, record: "p=QQ==; t=y:s", reason: ReasonInvalidKey},
		{name: testNameUnsupported, record: "k=future; p=QQ==; t=y:s", reason: ReasonUnsupportedKeyType},
		{name: testNameMismatch, record: "k=ed25519; p=" + manifest.Ed25519Raw + "; t=y:s", reason: ReasonKeyAlgorithmMismatch},
	} {
		t.Run(tt.name+" metadata", func(t *testing.T) {
			result := verifyDNSVector(context.Background(), t, corpus, goldenVectorRSAPass, mustDNSVectorProvider(t, &dnsVectorTransport{lookup: fixedPublicRecord(t, tt.record)}, DefaultDNSProviderConfig()))
			fact := result.SignatureSets()[0]
			metadata := fact.KeyPolicyMetadata()
			if fact.Reason() != tt.reason || !metadata.TestingDeclared() || !metadata.StrictIdentityDeclared() || metadata.StrictIdentityApplicable() {
				t.Fatalf("negative metadata = %q/%v/%v/%v", fact.Reason(), metadata.TestingDeclared(), metadata.StrictIdentityDeclared(), metadata.StrictIdentityApplicable())
			}
		})
	}

	failing := &dnsVectorTransport{lookup: func(_ context.Context, owner string) (TXTLookupResult, error) {
		if owner == dnsVectorEdOwner {
			return foundPublicTXT(t, manifest.Ed25519LowerTXT+"; t=y:s", DNSSECStatusUnavailable), nil
		}
		return foundPublicTXT(t, manifest.RSADefaultTXT, DNSSECStatusUnavailable), nil
	}}
	failResult := verifyDNSVector(context.Background(), t, corpus, "supported_mixed_fail", mustDNSVectorProvider(t, failing, DefaultDNSProviderConfig()))
	for _, fact := range failResult.SignatureSets() {
		if fact.Status() == SignatureStatusFAIL {
			metadata := fact.KeyPolicyMetadata()
			if !metadata.TestingDeclared() || !metadata.StrictIdentityDeclared() || metadata.StrictIdentityApplicable() {
				t.Fatalf("FAIL metadata = %#v", metadata)
			}
			return
		}
	}
	t.Fatal("missing DNS-backed FAIL signature fact")
}

// TestDNSDraft04DNSSECAndCacheHistoryAreInvisible verifies operational history neutrality.
func TestDNSDraft04DNSSECAndCacheHistoryAreInvisible(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	manifest := loadDNSGoldenManifest(t, corpus)
	var baseline publicResultSnapshot
	for index, dnssec := range []DNSSECStatus{DNSSECStatusSecure, DNSSECStatusInsecure, DNSSECStatusBogus, DNSSECStatusIndeterminate, DNSSECStatusUnavailable} {
		result := verifyDNSVector(context.Background(), t, corpus, goldenVectorRSAPass, mustDNSVectorProvider(t, dnsPassTransport(t, manifest.RSADefaultTXT, manifest.Ed25519LowerTXT, dnssec), DefaultDNSProviderConfig()))
		snapshot := snapshotPublicResult(result)
		if index == 0 {
			baseline = snapshot
		} else if !reflect.DeepEqual(snapshot, baseline) {
			t.Fatalf("DNSSEC class %q changed public facts", dnssec)
		}
	}

	var uncached publicResultSnapshot
	for _, cacheEntries := range []int{0, 4} {
		transport := dnsPassTransport(t, manifest.RSATestingStrictTXT, manifest.Ed25519LowerTXT+"; t=y:s", DNSSECStatusUnavailable)
		config := DefaultDNSProviderConfig()
		config.Limits.MaxCacheEntries = cacheEntries
		provider := mustDNSVectorProvider(t, transport, config)
		first := verifyDNSVector(context.Background(), t, corpus, "both_pass", provider)
		second := verifyDNSVector(context.Background(), t, corpus, "both_pass", provider)
		if !reflect.DeepEqual(snapshotPublicResult(first), snapshotPublicResult(second)) {
			t.Fatalf("cache capacity %d changed public facts", cacheEntries)
		}
		if cacheEntries == 0 {
			uncached = snapshotPublicResult(first)
		} else if !reflect.DeepEqual(snapshotPublicResult(first), uncached) {
			t.Fatal("cache-enabled facts differ from cache-disabled facts")
		}
		for _, fact := range first.SignatureSets() {
			metadata := fact.KeyPolicyMetadata()
			if !metadata.TestingDeclared() || !metadata.StrictIdentityDeclared() || metadata.StrictIdentityApplicable() {
				t.Fatalf("cache capacity %d metadata = %#v", cacheEntries, metadata)
			}
		}
		wantCalls := int32(4)
		if cacheEntries > 0 {
			wantCalls = 2
		}
		if transport.calls.Load() != wantCalls {
			t.Fatalf("cache capacity %d calls=%d want=%d", cacheEntries, transport.calls.Load(), wantCalls)
		}
	}
}

// TestDNSDraft04Context verifies caller errors and resolver-owned timeouts.
func TestDNSDraft04Context(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	manifest := loadDNSGoldenManifest(t, corpus)
	transport := dnsPassTransport(t, manifest.RSADefaultTXT, manifest.Ed25519LowerTXT, DNSSECStatusUnavailable)
	provider := mustDNSVectorProvider(t, transport, DefaultDNSProviderConfig())
	for _, tt := range []struct {
		build func() (context.Context, context.CancelFunc)
		want  error
	}{
		{build: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}
		}, want: context.Canceled},
		{build: func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), time.Unix(1, 0))
		}, want: context.DeadlineExceeded},
	} {
		ctx, cancel := tt.build()
		result, err := verifyDNSVectorResult(ctx, t, corpus, goldenVectorRSAPass, provider)
		cancel()
		if !errors.Is(err, tt.want) || !reflect.DeepEqual(result, VerifyResult{}) || transport.calls.Load() != 0 {
			t.Fatalf("canceled/deadline context error=%v calls=%d", err, transport.calls.Load())
		}
	}

	inFlightCtx, cancelInFlight := context.WithCancel(context.Background())
	inFlight := &dnsVectorTransport{lookup: func(ctx context.Context, _ string) (TXTLookupResult, error) {
		cancelInFlight()
		<-ctx.Done()
		return TXTLookupResult{}, ctx.Err()
	}}
	resultValue, err := verifyDNSVectorResult(inFlightCtx, t, corpus, goldenVectorRSAPass, mustDNSVectorProvider(t, inFlight, DefaultDNSProviderConfig()))
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(resultValue, VerifyResult{}) || inFlight.calls.Load() != 1 {
		t.Fatalf("in-flight cancellation result/error/calls = %#v/%v/%d", resultValue, err, inFlight.calls.Load())
	}

	timeoutConfig := DefaultDNSProviderConfig()
	timeoutConfig.Limits.LookupTimeout = time.Millisecond
	timeoutTransport := &dnsVectorTransport{lookup: func(ctx context.Context, _ string) (TXTLookupResult, error) {
		<-ctx.Done()
		return TXTLookupResult{}, ctx.Err()
	}}
	outer := context.Background()
	timed := verifyDNSVector(outer, t, corpus, goldenVectorRSAPass, mustDNSVectorProvider(t, timeoutTransport, timeoutConfig))
	timedSignatures := timed.SignatureSets()
	if timed.State() != ResultStateTEMPERROR || timed.PrimaryReason() != ReasonProviderTemporary || outer.Err() != nil || len(timedSignatures) != 1 || timedSignatures[0].Status() != SignatureStatusTEMPERROR {
		t.Fatalf("resolver timeout = %q/%q/%v", timed.State(), timed.PrimaryReason(), outer.Err())
	}
}

// TestDNSDraft04Precedence verifies exact mixed-result ordering and retained facts.
func TestDNSDraft04Precedence(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	manifest := loadDNSGoldenManifest(t, corpus)
	mixed := &dnsVectorTransport{lookup: func(_ context.Context, owner string) (TXTLookupResult, error) {
		if owner == dnsVectorRSAOwner {
			return TXTLookupResult{}, NewTemporaryProviderError()
		}
		return foundPublicTXT(t, "k=ed25519; p="+manifest.Ed25519Raw, DNSSECStatusUnavailable), nil
	}}
	result := verifyDNSVector(context.Background(), t, corpus, "supported_mixed_fail", mustDNSVectorProvider(t, mixed, DefaultDNSProviderConfig()))
	facts := snapshotPublicResult(result).Signatures
	checks := nonPassingPublicChecks(result)
	if result.State() != ResultStateFAIL || result.PrimaryReason() != ReasonSignatureMismatch || len(facts) != 2 ||
		!slices.Contains(facts, publicSignatureSnapshot{Algorithm: AlgorithmRSASHA256, Status: SignatureStatusTEMPERROR, Reason: ReasonProviderTemporary}) ||
		!slices.Contains(facts, publicSignatureSnapshot{Algorithm: AlgorithmEd25519SHA256, Status: SignatureStatusFAIL, Reason: ReasonSignatureMismatch}) ||
		len(checks) != 2 || !slices.Contains(checks, publicCheckSnapshot{Class: CheckClassProvider, Reason: ReasonProviderTemporary}) ||
		!slices.Contains(checks, publicCheckSnapshot{Class: CheckClassSignature, Reason: ReasonSignatureMismatch}) {
		t.Fatalf("FAIL precedence = %q/%q", result.State(), result.PrimaryReason())
	}

	mixed = &dnsVectorTransport{lookup: func(_ context.Context, owner string) (TXTLookupResult, error) {
		if owner == dnsVectorRSAOwner {
			return foundPublicTXT(t, "p=", DNSSECStatusUnavailable), nil
		}
		return TXTLookupResult{}, NewTemporaryProviderError()
	}}
	result = verifyDNSVector(context.Background(), t, corpus, "both_pass", mustDNSVectorProvider(t, mixed, DefaultDNSProviderConfig()))
	facts = snapshotPublicResult(result).Signatures
	checks = nonPassingPublicChecks(result)
	if result.State() != ResultStatePERMERROR || result.PrimaryReason() != ReasonRevokedKey || len(facts) != 2 ||
		!slices.Contains(facts, publicSignatureSnapshot{Algorithm: AlgorithmRSASHA256, Status: SignatureStatusPERMERROR, Reason: ReasonRevokedKey}) ||
		!slices.Contains(facts, publicSignatureSnapshot{Algorithm: AlgorithmEd25519SHA256, Status: SignatureStatusTEMPERROR, Reason: ReasonProviderTemporary}) ||
		len(checks) != 2 || !slices.Contains(checks, publicCheckSnapshot{Class: CheckClassKey, Reason: ReasonRevokedKey}) ||
		!slices.Contains(checks, publicCheckSnapshot{Class: CheckClassProvider, Reason: ReasonProviderTemporary}) {
		t.Fatalf("PERMERROR precedence = %q/%q", result.State(), result.PrimaryReason())
	}
}

// nonPassingPublicChecks returns the exact non-success check facts retained by one result.
func nonPassingPublicChecks(result VerifyResult) []publicCheckSnapshot {
	var checks []publicCheckSnapshot
	for _, check := range snapshotPublicResult(result).Checks {
		if check.Reason != ReasonNone {
			checks = append(checks, check)
		}
	}
	return checks
}

// expectedDNSStateChecks returns the exact sorted current-check fact set for one key/provider outcome.
func expectedDNSStateChecks(class CheckClass, reason ReasonCode) []publicCheckSnapshot {
	checks := []publicCheckSnapshot{
		{Class: CheckClassBodyHash, Reason: ReasonNone},
		{Class: CheckClassDomainAlignment, Reason: ReasonNone},
		{Class: CheckClassEnvelope, Reason: ReasonNone},
		{Class: CheckClassHeaderHash, Reason: ReasonNone},
	}
	if class == CheckClassKey {
		checks = append(checks, publicCheckSnapshot{Class: class, Reason: reason})
	}
	checks = append(checks, publicCheckSnapshot{Class: CheckClassNextDomain, Reason: ReasonNone})
	if class == CheckClassProvider {
		checks = append(checks, publicCheckSnapshot{Class: class, Reason: reason})
	}
	return append(checks, publicCheckSnapshot{Class: CheckClassTimestamp, Reason: ReasonNone})
}

// TestDNSDraft04CurrentIntegrityFailureCannotPass verifies valid DNS keys do not override current-message checks.
func TestDNSDraft04CurrentIntegrityFailureCannotPass(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	manifest := loadDNSGoldenManifest(t, corpus)
	result := verifyDNSVector(context.Background(), t, corpus, "body_mismatch", mustDNSVectorProvider(t, dnsPassTransport(t, manifest.RSADefaultTXT, manifest.Ed25519LowerTXT, DNSSECStatusUnavailable), DefaultDNSProviderConfig()))
	if result.State() != ResultStateFAIL || result.PrimaryReason() != ReasonHashMismatch || !slices.Contains(snapshotPublicResult(result).Checks, publicCheckSnapshot{Class: CheckClassBodyHash, Reason: ReasonHashMismatch}) {
		t.Fatalf("body mismatch = %q/%q", result.State(), result.PrimaryReason())
	}
}

// TestDNSDraft04PublicQueryHasNoLookupMethodSurface verifies no q= API was invented.
func TestDNSDraft04PublicQueryHasNoLookupMethodSurface(t *testing.T) {
	typeOfQuery := reflect.TypeFor[PublicKeyQuery]()
	for _, name := range []string{"Q", "QueryMethod", "LookupMethod"} {
		if _, ok := typeOfQuery.MethodByName(name); ok {
			t.Fatalf("unexpected public lookup method %q", name)
		}
	}
}

// dnsPassTransport constructs found public records for frozen RSA and Ed25519 owners.
func dnsPassTransport(t testing.TB, rsaRecord, edRecord string, dnssec DNSSECStatus) *dnsVectorTransport {
	t.Helper()
	return &dnsVectorTransport{lookup: func(_ context.Context, owner string) (TXTLookupResult, error) {
		switch owner {
		case dnsVectorRSAOwner:
			return foundPublicTXT(t, rsaRecord, dnssec), nil
		case dnsVectorEdOwner:
			return foundPublicTXT(t, edRecord, dnssec), nil
		default:
			return TXTLookupResult{}, errors.New("unexpected synthetic owner")
		}
	}}
}

// fixedPublicRecord returns one RSA-owner TXT record callback.
func fixedPublicRecord(t *testing.T, record string) func(context.Context, string) (TXTLookupResult, error) {
	t.Helper()
	return func(context.Context, string) (TXTLookupResult, error) {
		return foundPublicTXT(t, record, DNSSECStatusUnavailable), nil
	}
}

// fixedPublicAbsent returns one authoritative absence callback.
func fixedPublicAbsent(t *testing.T, absence TXTAbsenceClass) func(context.Context, string) (TXTLookupResult, error) {
	t.Helper()
	return func(context.Context, string) (TXTLookupResult, error) {
		result, err := NewAbsentTXTLookupResult(absence, time.Minute, DNSSECStatusUnavailable)
		if err != nil {
			t.Fatal("invalid synthetic absence")
		}
		return result, nil
	}
}

// fixedPublicAmbiguous returns one count-only ambiguous callback.
func fixedPublicAmbiguous(t *testing.T) func(context.Context, string) (TXTLookupResult, error) {
	t.Helper()
	return func(context.Context, string) (TXTLookupResult, error) {
		result, err := NewAmbiguousTXTLookupResult(2, time.Minute, DNSSECStatusUnavailable)
		if err != nil {
			t.Fatal("invalid synthetic ambiguity")
		}
		return result, nil
	}
}

// fixedPublicError returns one typed or unclassified provider callback.
func fixedPublicError(err error) func(context.Context, string) (TXTLookupResult, error) {
	return func(context.Context, string) (TXTLookupResult, error) { return TXTLookupResult{}, err }
}

// foundPublicTXT constructs one immutable synthetic TXT answer.
func foundPublicTXT(t testing.TB, record string, dnssec DNSSECStatus) TXTLookupResult {
	t.Helper()
	result, err := NewFoundTXTLookupResult([][]byte{[]byte(record)}, time.Minute, dnssec)
	if err != nil {
		t.Fatal("invalid synthetic TXT record")
	}
	return result
}

// mustDNSVectorProvider constructs a configured public DNS provider.
func mustDNSVectorProvider(t testing.TB, transport TXTTransport, config DNSProviderConfig) PublicKeyProvider {
	t.Helper()
	provider, err := NewDNSPublicKeyProviderWithConfig(transport, config)
	if err != nil {
		t.Fatal("DNS vector provider construction failed")
	}
	return provider
}

// verifyDNSVector verifies one frozen message through the public facade.
func verifyDNSVector(ctx context.Context, t *testing.T, corpus publicGoldenCorpus, name string, provider PublicKeyProvider) VerifyResult {
	t.Helper()
	result, err := verifyDNSVectorResult(ctx, t, corpus, name, provider)
	if err != nil {
		t.Fatalf("public vector %s returned Go error", name)
	}
	return result
}

// verifyDNSVectorResult returns the public result/error pair for one frozen vector.
func verifyDNSVectorResult(ctx context.Context, t *testing.T, corpus publicGoldenCorpus, name string, provider PublicKeyProvider) (VerifyResult, error) {
	t.Helper()
	vector, ok := corpus.Vectors[name]
	if !ok {
		t.Fatalf("missing public vector %q", name)
	}
	raw := decodeGoldenBytes(t, vector.Raw)
	reverse := decodeGoldenBytes(t, vector.Reverse)
	forward := decodeGoldenPaths(t, vector.Forward)
	verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		return VerifyResult{}, err
	}
	return verifier.Verify(ctx, NewVerifyRequest(raw, reverse, forward))
}

// snapshotPublicResult captures every public protocol fact for exact comparison.
func snapshotPublicResult(result VerifyResult) publicResultSnapshot {
	snapshot := publicResultSnapshot{
		Draft: result.Draft(), State: result.State(), Scope: result.Scope(),
		HistoricalContent: result.HistoricalContent(), HistoricalSignatures: result.HistoricalSignatures(),
		Reason: result.PrimaryReason(), Custody: result.CustodyStructure(),
		Target: [2]uint64{result.Target().Sequence(), result.Target().Instance()},
	}
	for _, fact := range result.Checks() {
		snapshot.Checks = append(snapshot.Checks, publicCheckSnapshot{Class: fact.Class(), Reason: fact.Reason()})
	}
	for _, fact := range result.SignatureSets() {
		metadata := fact.KeyPolicyMetadata()
		snapshot.Signatures = append(snapshot.Signatures, publicSignatureSnapshot{Algorithm: fact.Algorithm(), Status: fact.Status(), Reason: fact.Reason(), Testing: metadata.TestingDeclared(), Strict: metadata.StrictIdentityDeclared(), Applicable: metadata.StrictIdentityApplicable()})
	}
	return snapshot
}

// loadDNSGoldenManifest validates both active draft identifiers and public key encodings.
func loadDNSGoldenManifest(t testing.TB, corpus publicGoldenCorpus) dnsGoldenManifest {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors/draft-chuang-dkim2-dns-04/dns-golden.json")
	if err != nil {
		t.Fatal("DNS golden manifest unavailable")
	}
	var manifest dnsGoldenManifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.MessageDraft != DraftIdentifier || manifest.DNSDraft != "draft-chuang-dkim2-dns-04" {
		t.Fatal("invalid DNS golden manifest")
	}
	rsaDER := x509.MarshalPKCS1PublicKey(corpus.rsaKey(t))
	if base64.StdEncoding.EncodeToString(rsaDER) != manifest.RSAPKCS1 || base64.StdEncoding.EncodeToString(corpus.edKey(t)) != manifest.Ed25519Raw ||
		manifest.RSADefaultTXT != "p="+manifest.RSAPKCS1 || manifest.RSAExplicitTXT != "v=DKIM1; k=rsa; p="+manifest.RSAPKCS1 ||
		manifest.Ed25519LowerTXT != "v=DKIM1; k=ed25519; p="+manifest.Ed25519Raw || manifest.RSATestingTXT != manifest.RSADefaultTXT+"; t=y" ||
		manifest.RSAStrictTXT != manifest.RSADefaultTXT+"; t=s" || manifest.RSATestingStrictTXT != manifest.RSADefaultTXT+"; t=y:s" ||
		!slices.Equal(manifest.Owners, []string{dnsVectorRSAOwner, dnsVectorEdOwner}) {
		t.Fatal("DNS golden manifest public material mismatch")
	}
	return manifest
}
