package dkim2

import (
	"bytes"
	"context"
	"testing"
	"time"
)

type callCountingPublicProvider struct{ calls int }

// LookupPublicKey records facade-to-provider calls and reports a missing key.
func (p *callCountingPublicProvider) LookupPublicKey(_ context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
	p.calls++
	return MissingPublicKey(query.Algorithm()), nil
}

// TestFacadeAcceptsExactPublicLimitBoundaries verifies every public option reaches its exact service seam.
func TestFacadeAcceptsExactPublicLimitBoundaries(t *testing.T) {
	raw := publicProviderFixture(t)
	baselineProvider := &callCountingPublicProvider{}
	baseline, err := NewVerifier(baselineProvider, WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	baselineResult, err := baseline.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || baselineResult.PrimaryReason() != ReasonMissingKey {
		t.Fatalf("baseline Verify() = %q/%q, %v", baselineResult.State(), baselineResult.PrimaryReason(), err)
	}
	tests := []struct {
		name   string
		option VerifierOption
	}{
		{name: "raw", option: WithMaxRawMessageBytes(len(raw))},
		{name: "recipients", option: WithMaxRecipients(1)},
		{name: "hash sets", option: WithMaxInstanceHashSets(1)},
		{name: publicSignatureSetsTestName, option: WithMaxSignatureSets(1)},
		{name: "check facts", option: WithMaxCheckFacts(baselineResult.CheckCount())},
		{name: "signature facts", option: WithMaxSignatureFacts(baselineResult.SignatureSetCount())},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &callCountingPublicProvider{}
			verifier, constructErr := NewVerifier(provider, tt.option, WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
			if constructErr != nil {
				t.Fatalf("NewVerifier() error = %v", constructErr)
			}
			result, verifyErr := verifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			if verifyErr != nil || result.PrimaryReason() == ReasonLimitExceeded || provider.calls != 1 {
				t.Fatalf("Verify() = %q/%q calls=%d err=%v", result.State(), result.PrimaryReason(), provider.calls, verifyErr)
			}
		})
	}
}

// TestFacadeWiresPreProviderLimits verifies root options reach raw, recipient, and extraction seams.
func TestFacadeWiresPreProviderLimits(t *testing.T) {
	base := publicProviderFixture(t)
	tests := []struct {
		name       string
		raw        []byte
		recipients [][]byte
		options    []VerifierOption
	}{
		{name: "raw", raw: base, recipients: [][]byte{[]byte("<rcpt@example.test>")}, options: []VerifierOption{WithMaxRawMessageBytes(len(base) - 1)}},
		{name: "recipients", raw: base, recipients: [][]byte{[]byte("<rcpt@example.test>"), []byte("<other@example.test>")}, options: []VerifierOption{WithMaxRecipients(1)}},
		{name: "hash sets", raw: duplicateProtocolSet(base, []byte("h=")), recipients: [][]byte{[]byte("<rcpt@example.test>")}, options: []VerifierOption{WithMaxInstanceHashSets(1)}},
		{name: publicSignatureSetsTestName, raw: duplicateProtocolSet(base, []byte("s=")), recipients: [][]byte{[]byte("<rcpt@example.test>")}, options: []VerifierOption{WithMaxSignatureSets(1)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &callCountingPublicProvider{}
			options := append(tt.options, WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
			verifier, err := NewVerifier(provider, options...)
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			result, err := verifier.Verify(context.Background(), NewVerifyRequest(tt.raw, []byte("<>"), tt.recipients))
			if err != nil || result.State() != ResultStatePERMERROR || result.PrimaryReason() != ReasonLimitExceeded || provider.calls != 0 {
				t.Fatalf("Verify() = %q/%q calls=%d err=%v", result.State(), result.PrimaryReason(), provider.calls, err)
			}
		})
	}
}

// TestFacadeWiresPublicResultCaps verifies service facts cannot over-allocate public results.
func TestFacadeWiresPublicResultCaps(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	bothSupportedRaw := decodeGoldenBytes(t, corpus.Vectors["both_pass"].Raw)
	probeProvider := &callCountingPublicProvider{}
	probe, err := NewVerifier(probeProvider, WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier(probe) error = %v", err)
	}
	probeResult, err := probe.Verify(context.Background(), NewVerifyRequest(publicProviderFixture(t), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || probeResult.CheckCount() < 2 {
		t.Fatalf("probe Verify() checks=%d err=%v", probeResult.CheckCount(), err)
	}
	tests := []struct {
		name     string
		raw      []byte
		options  []VerifierOption
		checkCap int
		signCap  int
	}{
		{name: "checks", raw: publicProviderFixture(t), options: []VerifierOption{WithMaxCheckFacts(probeResult.CheckCount() - 1)}, checkCap: probeResult.CheckCount() - 1, signCap: HardMaxSignatureFacts},
		{name: "signatures", raw: bothSupportedRaw, options: []VerifierOption{WithMaxSignatureSets(2), WithMaxSignatureFacts(1)}, checkCap: HardMaxCheckFacts, signCap: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &callCountingPublicProvider{}
			options := append(tt.options, WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
			verifier, err := NewVerifier(provider, options...)
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			result, err := verifier.Verify(context.Background(), NewVerifyRequest(tt.raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			if err != nil || result.State() != ResultStatePERMERROR || result.PrimaryReason() != ReasonLimitExceeded || result.CheckCount() > tt.checkCap || result.SignatureSetCount() > tt.signCap {
				t.Fatalf("Verify() = %q/%q checks=%d signatures=%d err=%v", result.State(), result.PrimaryReason(), result.CheckCount(), result.SignatureSetCount(), err)
			}
		})
	}
}

// duplicateProtocolSet duplicates one comma-list item in the selected protocol tag.
func duplicateProtocolSet(raw, marker []byte) []byte {
	copyRaw := bytes.Clone(raw)
	start := bytes.Index(copyRaw, marker)
	if start < 0 {
		return copyRaw
	}
	start += len(marker)
	endOffset := bytes.IndexByte(copyRaw[start:], ';')
	if endOffset < 0 {
		return copyRaw
	}
	end := start + endOffset
	replacement := append(bytes.Clone(copyRaw[start:end]), ',')
	replacement = append(replacement, copyRaw[start:end]...)
	result := make([]byte, 0, len(copyRaw)+len(replacement))
	result = append(result, copyRaw[:start]...)
	result = append(result, replacement...)
	result = append(result, copyRaw[end:]...)
	return result
}
