package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/policy"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/verify"
)

type countingProvider struct{ calls int }

// LookupKey records calls and returns typed missing-key state.
func (p *countingProvider) LookupKey(context.Context, verify.KeyQuery) (verify.PublicKey, error) {
	p.calls++
	return verify.PublicKey{Metadata: verify.KeyMetadata{Status: verify.KeyStatusMissing}}, verify.NewProviderFailure(verify.ProviderFailurePermanent)
}

// TestVerifierMapsSequenceExtractionFailureToUnevaluatedCustody verifies failed extraction makes no nd= claim.
func TestVerifierMapsSequenceExtractionFailureToUnevaluatedCustody(t *testing.T) {
	const timestamp = uint64(1700000000)
	raw := strings.Replace(string(syntheticCurrentMessage(t, timestamp, 1, 1)), "DKIM2-Signature: i=1;", "DKIM2-Signature: i=2;", 1)
	config := DefaultConfig()
	config.Clock = func() time.Time { return time.Unix(int64(timestamp), 0) }
	verifier, err := NewVerifier(&countingProvider{}, config)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewRequest([]byte(raw), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonSequenceInvalid || result.Custody() != CustodyNotEvaluated {
		t.Fatalf("result = %q/%q/%q", result.State(), result.PrimaryReason(), result.Custody())
	}
	projection := result.PolicyProjection()
	if result.Target() != (Target{}) || !projection.Valid() || projection.Form() != policy.TargetUnavailable || projection.PreTargetReason() != policy.PreTargetSequenceInvalid {
		t.Fatalf("sequence projection = target=%#v projection=%#v", result.Target(), projection)
	}
}

// TestVerifierMapsDuplicateSequenceDiagnosticToUnavailableTarget verifies diagnostic i= is not authoritative.
func TestVerifierMapsDuplicateSequenceDiagnosticToUnavailableTarget(t *testing.T) {
	const timestamp = uint64(1700000000)
	raw := string(syntheticCurrentMessage(t, timestamp, 1, 1))
	start := strings.Index(raw, "DKIM2-Signature:")
	end := strings.Index(raw[start:], "\r\n")
	if start < 0 || end < 0 {
		t.Fatal("synthetic message lacks signature header")
	}
	line := raw[start : start+end+2]
	raw = raw[:start] + line + raw[start:]
	config := DefaultConfig()
	config.Clock = func() time.Time { return time.Unix(int64(timestamp), 0) }
	verifier, err := NewVerifier(&countingProvider{}, config)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewRequest([]byte(raw), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	projection := result.PolicyProjection()
	if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonSequenceInvalid || result.Target() != (Target{}) ||
		!projection.Valid() || projection.Form() != policy.TargetUnavailable || projection.PreTargetReason() != policy.PreTargetSequenceInvalid {
		t.Fatalf("duplicate result = %q/%q target=%#v projection=%#v", result.State(), result.PrimaryReason(), result.Target(), projection)
	}
}

// TestMalformedStateTargetClassificationPreservesPostSelectionDiagnostics verifies location-aware provenance.
func TestMalformedStateTargetClassificationPreservesPostSelectionDiagnostics(t *testing.T) {
	if !verificationErrorHasUnavailableTarget(verify.ErrorCodeMalformedState, Target{}) {
		t.Fatal("pre-target malformed state was not classified unavailable")
	}
	for _, partial := range []Target{{Sequence: 1}, {Instance: 1}} {
		if !verificationErrorHasUnavailableTarget(verify.ErrorCodeCustodyMismatch, partial) {
			t.Fatalf("partial target %#v was not classified unavailable", partial)
		}
	}
	if verificationErrorHasUnavailableTarget(verify.ErrorCodeMalformedState, Target{Sequence: 1, Instance: 1}) {
		t.Fatal("post-selection malformed state was classified target unavailable")
	}
}

// TestStructuralChainErrorsNormalizeToUnavailableMalformedProtocol proves the complete pre-target mapping matrix.
func TestStructuralChainErrorsNormalizeToUnavailableMalformedProtocol(t *testing.T) {
	for _, code := range []verify.ErrorCode{
		verify.ErrorCodeCustodyMismatch,
		verify.ErrorCodeNextDomainMismatch,
		verify.ErrorCodeMissingNextSignature,
	} {
		t.Run(string(code), func(t *testing.T) {
			target := Target{Sequence: 2}
			reason, class, state := mapVerificationErrorCode(code)
			if !verificationErrorHasUnavailableTarget(code, target) {
				t.Fatal("partial structural target was treated as authoritative")
			}
			target = Target{}
			reason, class, state = unavailableVerificationFailure(code, reason, class, state)
			projection, err := buildUnavailablePolicyProjection(reason)
			if err != nil || target != (Target{}) || reason != ReasonMalformedProtocol || class != CheckProtocol || state != StatePERMERROR ||
				!projection.Valid() || projection.Form() != policy.TargetUnavailable || projection.PreTargetReason() != policy.PreTargetMalformedProtocol {
				t.Fatalf("mapping = target=%#v %q/%q/%q projection=%#v error=%v", target, reason, class, state, projection, err)
			}
		})
	}
}

// TestVerifierPreservesEvaluatedCustodyOnNextDomainMismatch verifies service error mapping.
func TestVerifierPreservesEvaluatedCustodyOnNextDomainMismatch(t *testing.T) {
	digest := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	signature := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 128))
	raw := "From: sender@example.test\r\n" +
		"Message-Instance: m=1; h=sha256:" + digest + ":" + digest + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1700000000; nd=wrong.example.test; d=first.example.test; s=selector.test:rsa-sha256:" + signature + ";\r\n" +
		"DKIM2-Signature: i=2; m=1; t=1700000000; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=next.example.test; s=selector.test:rsa-sha256:" + signature + ";\r\n\r\nbody\r\n"
	provider := &countingProvider{}
	config := DefaultConfig()
	config.Clock = func() time.Time { return time.Unix(1700000000, 0) }
	verifier, err := NewVerifier(provider, config)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewRequest([]byte(raw), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	projection := result.PolicyProjection()
	if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonMalformedProtocol || result.Custody() != CustodyNDLinksEvaluated || result.Target() != (Target{}) ||
		!projection.Valid() || projection.Form() != policy.TargetUnavailable || projection.PreTargetReason() != policy.PreTargetMalformedProtocol {
		t.Fatalf("result = %q/%q/%q", result.State(), result.PrimaryReason(), result.Custody())
	}
	if provider.calls != 0 {
		t.Fatalf("provider calls = %d, want zero", provider.calls)
	}
}

// TestVerifierDoesNotClaimAbsentCustodyWhenInstancesAreMissing verifies signature evidence remains indeterminate.
func TestVerifierDoesNotClaimAbsentCustodyWhenInstancesAreMissing(t *testing.T) {
	signatureText := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 128))
	raw := "From: sender@example.test\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1700000000; nd=next.example.test; d=first.example.test; s=selector.test:rsa-sha256:" + signatureText + ";\r\n\r\nbody\r\n"
	provider := &countingProvider{}
	config := DefaultConfig()
	config.Clock = func() time.Time { return time.Unix(1700000000, 0) }
	verifier, err := NewVerifier(provider, config)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewRequest([]byte(raw), nil, nil))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.PrimaryReason() != ReasonMissingProtocol || result.Custody() != CustodyNotEvaluated || provider.calls != 0 {
		t.Fatalf("missing-instance result=%s/%s provider_calls=%d", result.PrimaryReason(), result.Custody(), provider.calls)
	}
}

// TestVerifierMapsOrdinaryAdjacencyMismatchAsMalformedProtocol verifies public custody failure taxonomy.
func TestVerifierMapsOrdinaryAdjacencyMismatchAsMalformedProtocol(t *testing.T) {
	digest := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	signatureText := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 128))
	raw := "From: sender@example.test\r\n" +
		"Message-Instance: m=1; h=sha256:" + digest + ":" + digest + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1700000000; mf=PGFAb3JpZ2luLnRlc3Q+; rt=PGJAcmVsYXkudGVzdD4=; d=origin.test; s=selector.test:rsa-sha256:" + signatureText + ";\r\n" +
		"DKIM2-Signature: i=2; m=1; t=1700000000; mf=PGJAZXZpbC50ZXN0Pg==; rt=PGNAZmluYWwudGVzdD4=; d=evil.test; s=selector.test:rsa-sha256:" + signatureText + ";\r\n\r\nbody\r\n"
	provider := &countingProvider{}
	config := DefaultConfig()
	config.Clock = func() time.Time { return time.Unix(1700000000, 0) }
	verifier, err := NewVerifier(provider, config)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewRequest([]byte(raw), nil, nil))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonMalformedProtocol || provider.calls != 0 {
		t.Fatalf("adjacency result=%s/%s provider_calls=%d", result.State(), result.PrimaryReason(), provider.calls)
	}
	projection := result.PolicyProjection()
	if result.Target() != (Target{}) || !projection.Valid() || projection.Form() != policy.TargetUnavailable || projection.PreTargetReason() != policy.PreTargetMalformedProtocol {
		t.Fatalf("adjacency target=%#v projection=%#v", result.Target(), projection)
	}
}

type failingProvider struct{ class verify.ProviderFailureClass }

// LookupKey returns one typed provider failure for integration mapping.
func (p failingProvider) LookupKey(context.Context, verify.KeyQuery) (verify.PublicKey, error) {
	return verify.PublicKey{}, verify.NewProviderFailure(p.class)
}

type dereferencingProvider struct{ calls int }

// LookupKey deliberately dereferences its receiver to expose typed-nil construction defects.
func (p *dereferencingProvider) LookupKey(context.Context, verify.KeyQuery) (verify.PublicKey, error) {
	p.calls++
	return verify.PublicKey{}, nil
}

// TestNewVerifierRejectsTypedNilProvider verifies invalid interface dependencies fail at construction.
func TestNewVerifierRejectsTypedNilProvider(t *testing.T) {
	var provider *dereferencingProvider
	verifier, err := NewVerifier(provider, DefaultConfig())
	if err == nil || verifier.initialized {
		t.Fatalf("NewVerifier(typed nil) = %#v, %v", verifier, err)
	}
}

// TestVerifierRejectsPreExtractionLimitsBeforeProvider verifies exact early ownership seams.
func TestVerifierRejectsPreExtractionLimitsBeforeProvider(t *testing.T) {
	provider := &countingProvider{}
	config := DefaultConfig()
	config.Limits.MaxRawMessageBytes = 8
	verifier, err := NewVerifier(provider, config)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	result, err := verifier.Verify(context.Background(), NewRequest([]byte("From: a\r\n"), []byte("<>"), nil))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonLimitExceeded || result.Custody() != CustodyNotEvaluated {
		t.Fatalf("result = %q/%q/%q", result.State(), result.PrimaryReason(), result.Custody())
	}
	if provider.calls != 0 {
		t.Fatalf("provider calls = %d, want zero", provider.calls)
	}
}

// TestVerifierMapsMalformedInputWithoutRawDiagnostics verifies protocol errors remain results.
func TestVerifierMapsMalformedInputWithoutRawDiagnostics(t *testing.T) {
	provider := &countingProvider{}
	verifier, err := NewVerifier(provider, DefaultConfig())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewRequest([]byte("RAW-SECRET-BARE-LF\n"), nil, nil))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.State() != StatePERMERROR || result.PrimaryReason() != ReasonMalformedMessage || result.Custody() != CustodyNotEvaluated {
		t.Fatalf("result = %q/%q/%q", result.State(), result.PrimaryReason(), result.Custody())
	}
	if provider.calls != 0 {
		t.Fatalf("provider calls = %d, want zero", provider.calls)
	}
}

// TestVerifierReturnsCallerContextAsGoError verifies result/error disjointness.
func TestVerifierReturnsCallerContextAsGoError(t *testing.T) {
	verifier, err := NewVerifier(&countingProvider{}, DefaultConfig())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := verifier.Verify(ctx, Request{})
	if !errors.Is(err, context.Canceled) || result.Draft() != "" || result.State() != "" {
		t.Fatalf("Verify() = %#v, %v; want zero result and context.Canceled", result, err)
	}
}

// TestZeroVerifierReturnsAPIMisuseError verifies uninitialized coordinators cannot produce protocol results.
func TestZeroVerifierReturnsAPIMisuseError(t *testing.T) {
	for _, request := range []Request{{}, NewRequest([]byte("From: sender@example.test\r\n"), nil, nil)} {
		result, err := (Verifier{}).Verify(context.Background(), request)
		if err == nil || result.Draft() != "" || result.State() != "" {
			t.Fatalf("zero Verifier.Verify() = %#v, %v", result, err)
		}
	}
}

// TestVerifierMapsRealTypedProviderFailures verifies the core-to-service provider path.
func TestVerifierMapsRealTypedProviderFailures(t *testing.T) {
	const timestamp = uint64(1700000000)
	raw := syntheticCurrentMessage(t, timestamp, 1, 1)
	tests := []struct {
		name   string
		class  verify.ProviderFailureClass
		state  State
		reason Reason
	}{
		{name: "temporary", class: verify.ProviderFailureTemporary, state: StateTEMPERROR, reason: ReasonProviderTemporary},
		{name: "permanent", class: verify.ProviderFailurePermanent, state: StatePERMERROR, reason: ReasonProviderPermanent},
		{name: "contract", class: verify.ProviderFailureContract, state: StatePERMERROR, reason: ReasonProviderContract},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.Clock = func() time.Time { return time.Unix(int64(timestamp), 0) }
			verifier, err := NewVerifier(failingProvider{class: tt.class}, config)
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			result, err := verifier.Verify(context.Background(), NewRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.State() != tt.state || result.PrimaryReason() != tt.reason || result.Custody() != CustodyNotPresent {
				t.Fatalf("result = %q/%q/%q", result.State(), result.PrimaryReason(), result.Custody())
			}
		})
	}
}

// syntheticCurrentMessage builds parser-valid current input with exact SHA-256 hashes.
func syntheticCurrentMessage(t *testing.T, timestamp uint64, hashSets, signatureSets int) []byte {
	t.Helper()
	base := []byte("From: sender@example.test\r\nSubject: service mapping\r\n\r\nbody line\r\n")
	message, err := rawmsg.Parse(base)
	if err != nil {
		t.Fatalf("rawmsg.Parse(base) error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	headerHash, err := canonicalizer.HeaderHashFromMessage(message)
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error = %v", err)
	}
	bodyHash, err := canonicalizer.BodyHashFromMessage(message)
	if err != nil {
		t.Fatalf("BodyHashFromMessage() error = %v", err)
	}
	headerDigest, _ := headerHash.Digest()
	bodyDigest, _ := bodyHash.Digest()
	hashSet := "sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64()
	hashes := bytes.Join(bytesMatrix([]byte(hashSet), hashSets), []byte(","))
	signatureSet := []byte("selector.test:rsa-sha256:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 128)))
	signatures := bytes.Join(bytesMatrix(signatureSet, signatureSets), []byte(","))
	raw := "From: sender@example.test\r\nSubject: service mapping\r\n" +
		"Message-Instance: m=1; h=" + string(hashes) + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=" + strconv.FormatUint(timestamp, 10) + "; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=example.test; s=" + string(signatures) + ";\r\n\r\nbody line\r\n"
	return []byte(raw)
}

// bytesMatrix returns independent repeated byte slices for synthetic lists.
func bytesMatrix(value []byte, count int) [][]byte {
	result := make([][]byte, count)
	for index := range result {
		result[index] = bytes.Clone(value)
	}
	return result
}
